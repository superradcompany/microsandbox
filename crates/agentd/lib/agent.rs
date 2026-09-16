//! Main agent loop: serial I/O, session management, heartbeat.

use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::BytesMut;
use chrono::Utc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::{self, Duration};

use microsandbox_protocol::AGENT_TRANSPORT_DUAL_PORT_CMDLINE;
use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_protocol::bulk::{
    BULK_HEADER_SIZE, BULK_PROTOCOL_VERSION, BulkCancel, BulkCancelReason, BulkCredit, BulkFinish,
    BulkFlow, BulkKind, BulkRecord, DEFAULT_BULK_WINDOW, DEFAULT_FILESYSTEM_BULK_RECORD_PAYLOAD,
    MAX_BULK_RECORD_PAYLOAD, MIN_BULK_RECORD_PAYLOAD,
};
use microsandbox_protocol::codec::{self, DecodedFrame, MAX_FRAME_SIZE};
use microsandbox_protocol::core::{
    ClockSync, CoreError, CoreErrorKind, InitAck, InitResolved, Ping, Pong, Ready,
    RelayClientDisconnected, ResolvedUser, Touch, Touched, WORKLOAD_TRANSPORT_BARRIER_VERSION,
    WORKLOAD_TRANSPORT_BULK_BYTES, WORKLOAD_TRANSPORT_BULK_FRAMES,
    WORKLOAD_TRANSPORT_CONTROL_BYTES, WORKLOAD_TRANSPORT_CONTROL_FRAMES, WorkloadFailure,
    WorkloadFailureDisposition, WorkloadFreeze, WorkloadFrozen, WorkloadThaw, WorkloadThawed,
    WorkloadTransportCredit, WorkloadTransportPosition,
};
use microsandbox_protocol::exec::{
    ExecExited, ExecFailed, ExecFailureKind, ExecRequest, ExecResize, ExecSignal, ExecStarted,
    ExecStderr, ExecStdin, ExecStdinError, ExecStdout,
};
use microsandbox_protocol::fs::{FS_CHUNK_SIZE, FsData, FsRequest, FsResponse};
use microsandbox_protocol::heartbeat::{ActivityCounters, Heartbeat};
use microsandbox_protocol::message::{FRAME_HEADER_SIZE, Message, MessageType};
use microsandbox_protocol::tcp::{TcpClose, TcpConnect, TcpData, TcpEof, TcpFailed};
use microsandbox_protocol::transport::{
    BULK_BINDING_SIZE, BulkTransportReady, CLIENT_INCARNATION_SIZE, ClientIncarnation,
    IncarnatedBulkFrame, RelayClientConnected, RelayClientDisconnectedAck, RelayLeaseReady,
    decode_bulk_ack, encode_bulk_hello, encode_relay_client_disconnected_ack,
    relay_client_id_range, relay_client_slot, try_decode_incarnated_bulk_from_bytes,
    try_decode_relay_client_connected_from_bytes,
    try_decode_relay_client_disconnected_ack_from_bytes,
    validate_relay_client_range as canonical_relay_client_range,
};

use crate::config::{AgentdConfig, scripts_path};
use crate::error::{AgentdError, AgentdResult};
use crate::fs::{FsReadSession, FsState, FsStreamSession, FsWriteSession};
use crate::process::ProcessManager;
use crate::serial::{AGENT_BULK_PORT_NAME, AGENT_PORT_NAME, InputCharge, InputLane, InputWindow};
use crate::session::{
    BulkOutputCommand, ExecSession, RawActivity, RawSessionCompletion, RawSessionOutput,
    SessionOutput, SessionOutputEnvelope, SessionOutputSender, resolve_default_user,
};
use crate::tcp::TcpSession;
use crate::workload::{WorkloadLatch, WorkloadLatchError};
use crate::{clock, fs, handoff, heartbeat, serial};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Heartbeat interval in seconds.
///
/// Keep this short so small idle timeouts (for example `--idle-timeout 1`)
/// can be enforced without multi-second scheduling drift.
const HEARTBEAT_INTERVAL_SECS: u64 = 1;

/// Read buffer size for the serial port.
/// Control-only serial reads stay cache-friendly because their frames are small.
const CONTROL_SERIAL_READ_BUF_SIZE: usize = 64 * 1024;

/// Combined transport can receive any negotiated raw record without avoidable read cycles.
const COMBINED_SERIAL_READ_BUF_SIZE: usize = DEFAULT_FILESYSTEM_BULK_RECORD_PAYLOAD as usize + 32;

/// Dedicated bulk reads can consume one negotiated record in a single syscall when available.
const BULK_SERIAL_READ_BUF_SIZE: usize =
    DEFAULT_FILESYSTEM_BULK_RECORD_PAYLOAD as usize + CLIENT_INCARNATION_SIZE + 32;

/// Maximum allowed input buffer size (frame size limit + 4 bytes for length prefix).
const MAX_INPUT_BUF_SIZE: usize = MAX_FRAME_SIZE as usize + 4;

/// Dedicated records additionally carry the transport-level client incarnation.
const MAX_BULK_INPUT_BUF_SIZE: usize = MAX_INPUT_BUF_SIZE + CLIENT_INCARNATION_SIZE;

/// Bound actual console work between runtime scheduling points, independently of wire records.
/// Partial records count too: a readable bulk port must not hide fresh primary/PTY readiness.
const AGENT_READ_QUANTUM_BYTES: usize = 256 * 1024;
const AGENT_READ_QUANTUM_CALLS: usize = 64;

/// Maximum time to wait for the host to acknowledge the init context.
const INIT_ACK_TIMEOUT_SECS: u64 = 60;

/// Startup window shared by bulk-port discovery and binding.
const BULK_BINDING_TIMEOUT_SECS: u64 = 60;

/// Per-correlation quantum used by the dedicated guest-to-host scheduler.
const BULK_SCHEDULER_QUANTUM: usize = 256 * 1024;

/// Maximum bytes one correlation may emit in one scheduler round.
const BULK_SCHEDULER_MAX_BURST: usize = MAX_BULK_RECORD_PAYLOAD as usize;

/// Maximum bytes queued for one correlation outside the console backend.
const BULK_SCHEDULER_FLOW_CAPACITY: usize = 8 * 1024 * 1024;

/// Maximum active bulk correlations owned by one relay client.
const BULK_SCHEDULER_MAX_FLOWS_PER_CLIENT: usize = 64;

/// Whole records processed before the bulk reader yields on a one-vCPU guest.
const BULK_READER_MAX_RECORDS_PER_TURN: usize = 64;

/// Payload bytes processed before the bulk reader yields on a one-vCPU guest.
const BULK_READER_MAX_BYTES_PER_TURN: usize = 1024 * 1024;

/// Enough data slots for the default byte window at the smallest negotiated record size.
const FS_BULK_INPUT_ITEM_CAPACITY: usize =
    DEFAULT_BULK_WINDOW as usize / MIN_BULK_RECORD_PAYLOAD as usize;

/// Aggregate host-to-guest payload retained across every relay client and bulk destination.
const BULK_INPUT_BYTE_CAPACITY: usize = 32 * 1024 * 1024;

/// Filesystem activity bytes coalesced before publishing an otherwise empty worker event.
const FS_ACTIVITY_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Maximum contiguous payload coalesced into one guest filesystem effect.
const FS_BULK_WRITE_COALESCE_BYTES: usize = FS_CHUNK_SIZE;

/// Byte and time bounds for coalescing bulk-only heartbeat publications.
const BULK_ACTIVITY_PUBLISH_BYTES: usize = 4 * 1024 * 1024;
const BULK_ACTIVITY_PUBLISH_INTERVAL: Duration = Duration::from_millis(100);

/// Best-effort window for publishing typed cancellation before agentd terminates a failed lane.
const BULK_FAILURE_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct AgentState {
    input_window: InputWindow,
    pending_freeze: Option<Message>,
    aborted_transport_attempt: Option<String>,
    output_parked: bool,
    resume_output_after_flush: bool,
    frozen_host_input: Option<WorkloadTransportPosition>,
    frozen_guest_bulk_bytes: u64,
    // Retain stdin/PTY and process registrations until inherited output readers finish.
    detached_sessions: HashMap<(u64, u32), ExecSession>,
    stdin_poll_offset: usize,
    restored_attempt: Option<String>,
    client_incarnations: HashMap<u32, ClientIncarnation>,
    bulk_input_budget: Arc<Semaphore>,
    sessions: HashMap<u32, ExecSession>,
    write_sessions: HashMap<u32, FsWriteSession>,
    bulk_write_workers: HashMap<u32, FsBulkWriteWorker>,
    read_sessions: HashMap<u32, FsReadSession>,
    tcp_sessions: HashMap<u32, TcpSession>,
    bulk_received_offsets: HashMap<u32, u64>,
    pending_bulk_finishes: HashMap<u32, BulkFinish>,
    fs: FsState,
}

/// Bounded command path for one filesystem bulk write, isolated from the control loop.
struct FsBulkWriteWorker {
    records: tokio::sync::mpsc::Sender<AdmittedBulkRecord>,
    finish: tokio::sync::mpsc::Sender<BulkFinish>,
    task: tokio::task::JoinHandle<()>,
}

/// One host-to-guest record whose global input capacity remains charged until the destination
/// filesystem or TCP socket has consumed its payload.
pub(crate) struct AdmittedBulkRecord {
    record: BulkRecord,
    _permit: OwnedSemaphorePermit,
    _transport_charge: Option<InputCharge>,
}

/// Both budgets follow the payload all the way into asynchronous TCP/filesystem consumption.
pub(crate) struct BulkInputPermit {
    _payload: OwnedSemaphorePermit,
    _transport: Option<InputCharge>,
}

/// Dedicated-lane input waiting for aggregate client capacity while the control actor stays live.
struct PendingBulkInput {
    frame: IncarnatedBulkFrame,
    budget: Arc<Semaphore>,
    charge: InputCharge,
}

struct ActivityTracker {
    activity_seq: u64,
    counters: ActivityCounters,
}

/// Buffered console input retained across the bootstrap and init handshakes.
///
/// A single device read may contain multiple frames, so boot phases must share
/// this buffer instead of dropping bytes after decoding their expected frame.
#[derive(Default)]
pub struct BootConsoleState {
    input: Vec<u8>,
}

#[derive(Clone)]
struct HeartbeatSnapshot {
    activity_seq: u64,
    active_exec_sessions: u32,
    active_fs_streams: u32,
    active_tcp_streams: u32,
    counters: ActivityCounters,
}

/// Successfully bound second console port and its per-boot identity.
pub struct BoundBulkPort {
    file: File,
    connection_id: [u8; 16],
}

/// Dedicated-lane input owned by the main agent actor.
///
/// Keeping framing here removes the reader-task/channel round trip while bounded turns still give
/// control work a scheduling point between filesystem or TCP bursts.
struct BulkInputState {
    port: AsyncFd<File>,
    read_buf: Vec<u8>,
    input: BytesMut,
}

/// Shared primary/bulk work retained across select turns, including incomplete wire records.
#[derive(Default)]
struct AgentReadBudget {
    bytes: usize,
    calls: usize,
}

/// One correlation's pending records in the guest-to-host DRR scheduler.
struct BulkWriteFlow {
    queue: VecDeque<SessionOutputEnvelope>,
    queued_bytes: usize,
    deficit: usize,
}

/// Deferred acknowledgement after the scheduler has discarded already-queued producer output.
enum BulkOutputCleanup {
    Park {
        completion: tokio::sync::oneshot::Sender<u64>,
        wire_bytes: u64,
    },
    Flow(tokio::sync::oneshot::Sender<()>),
    Incarnation {
        incarnation: ClientIncarnation,
        completion: tokio::sync::oneshot::Sender<()>,
    },
}

#[derive(Default)]
struct BulkOutputPosition {
    parked: bool,
    wire_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Default for AgentState {
    fn default() -> Self {
        Self {
            input_window: InputWindow::new(initial_input_credit()),
            pending_freeze: None,
            aborted_transport_attempt: None,
            output_parked: false,
            resume_output_after_flush: false,
            frozen_host_input: None,
            frozen_guest_bulk_bytes: 0,
            detached_sessions: HashMap::new(),
            stdin_poll_offset: 0,
            restored_attempt: None,
            client_incarnations: HashMap::new(),
            bulk_input_budget: Arc::new(Semaphore::new(BULK_INPUT_BYTE_CAPACITY)),
            sessions: HashMap::new(),
            write_sessions: HashMap::new(),
            bulk_write_workers: HashMap::new(),
            read_sessions: HashMap::new(),
            tcp_sessions: HashMap::new(),
            bulk_received_offsets: HashMap::new(),
            pending_bulk_finishes: HashMap::new(),
            fs: FsState::default(),
        }
    }
}

impl AdmittedBulkRecord {
    pub(crate) fn record(&self) -> &BulkRecord {
        &self.record
    }

    pub(crate) fn into_parts(self) -> (BulkRecord, BulkInputPermit) {
        (
            self.record,
            BulkInputPermit {
                _payload: self._permit,
                _transport: self._transport_charge,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test(record: BulkRecord) -> Self {
        let payload_len = record.payload.len();
        let budget = Arc::new(Semaphore::new(payload_len));
        let permit = budget
            .try_acquire_many_owned(payload_len as u32)
            .expect("test record fits its exact input budget");
        Self {
            record,
            _permit: permit,
            _transport_charge: None,
        }
    }
}

impl ActivityTracker {
    fn new() -> Self {
        Self {
            activity_seq: 0,
            counters: ActivityCounters::default(),
        }
    }

    fn record_host_message(&mut self) {
        self.touch();
        self.counters.host_messages = self.counters.host_messages.saturating_add(1);
    }

    fn record_guest_message(&mut self) {
        self.touch();
        self.counters.guest_messages = self.counters.guest_messages.saturating_add(1);
    }

    fn add_exec_output_bytes(&mut self, len: usize) {
        self.counters.exec_output_bytes =
            self.counters.exec_output_bytes.saturating_add(len as u64);
    }

    fn add_fs_bytes(&mut self, len: usize) {
        self.counters.fs_bytes = self.counters.fs_bytes.saturating_add(len as u64);
    }

    fn add_tcp_bytes(&mut self, len: usize) {
        self.counters.tcp_bytes = self.counters.tcp_bytes.saturating_add(len as u64);
    }

    fn touch(&mut self) {
        self.activity_seq = self.activity_seq.saturating_add(1);
    }
}

impl BulkInputState {
    fn new(file: File) -> AgentdResult<Self> {
        Ok(Self {
            port: AsyncFd::new(file)?,
            read_buf: vec![0u8; BULK_SERIAL_READ_BUF_SIZE],
            input: BytesMut::new(),
        })
    }

    /// Read at most once, then return one bounded batch already available to the actor.
    async fn read_turn(
        &mut self,
        read_budget: &mut AgentReadBudget,
    ) -> AgentdResult<Vec<IncarnatedBulkFrame>> {
        let buffered = self.drain_turn()?;
        if !buffered.is_empty() {
            return Ok(buffered);
        }

        let mut guard = self.port.readable().await?;
        match guard
            .try_io(|inner| read_budget.read_fd(inner.get_ref().as_raw_fd(), &mut self.read_buf))
        {
            Ok(Ok(0)) => {
                return Err(AgentdError::ExecSession(
                    "dedicated bulk port closed".into(),
                ));
            }
            Ok(Ok(read)) => {
                self.input.extend_from_slice(&self.read_buf[..read]);
                if self.input.len() > MAX_BULK_INPUT_BUF_SIZE {
                    return Err(AgentdError::ExecSession(
                        "dedicated bulk input exceeded maximum frame buffer".into(),
                    ));
                }
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_would_block) => {}
        }
        self.drain_turn()
    }

    fn drain_turn(&mut self) -> AgentdResult<Vec<IncarnatedBulkFrame>> {
        let mut frames = Vec::new();
        let mut fs_bytes = 0usize;
        let mut tcp_bytes = 0usize;
        while frames.len() < BULK_READER_MAX_RECORDS_PER_TURN
            && fs_bytes < MAX_BULK_RECORD_PAYLOAD as usize
            && tcp_bytes < BULK_READER_MAX_BYTES_PER_TURN
        {
            let Some(frame) = try_decode_incarnated_bulk_from_bytes(&mut self.input)
                .map_err(|error| AgentdError::ExecSession(format!("decode agent-bulk: {error}")))?
            else {
                break;
            };
            match frame.record.kind {
                BulkKind::Filesystem => {
                    fs_bytes = fs_bytes.saturating_add(frame.record.payload.len());
                }
                BulkKind::Tcp => {
                    tcp_bytes = tcp_bytes.saturating_add(frame.record.payload.len());
                }
            }
            frames.push(frame);
        }
        Ok(frames)
    }
}

impl AgentReadBudget {
    fn read_fd(&mut self, fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = read_from_fd(fd, buf);
        self.record_read(result.as_ref().copied().unwrap_or(0));
        result
    }

    fn record_read(&mut self, bytes: usize) {
        self.calls = self.calls.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn exhausted(&self) -> bool {
        self.bytes >= AGENT_READ_QUANTUM_BYTES || self.calls >= AGENT_READ_QUANTUM_CALLS
    }

    /// Call outside the competing select futures, after decoded records have an owning queue.
    /// AsyncFd::readable can stay immediately ready without spending Tokio's cooperative budget;
    /// returning to select alone does not let the driver discover a writable PTY or new control IO.
    async fn yield_if_exhausted(&mut self) {
        if self.exhausted() {
            tokio::task::yield_now().await;
            *self = Self::default();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Runs the main agent loop.
///
/// Reuses the already-open virtio serial port, sends `core.ready` with boot timing data,
/// then enters the main select loop handling serial I/O, process output, and heartbeat.
///
/// - `boot_time_ns`: `CLOCK_BOOTTIME` at `main()` start (kernel boot duration).
/// - `init_time_ns`: nanoseconds spent in `init::init()`.
pub async fn run(
    boot_time_ns: u64,
    init_time_ns: u64,
    config: &AgentdConfig,
    port_file: File,
    boot_console: BootConsoleState,
    bulk_port: Option<BoundBulkPort>,
) -> AgentdResult<()> {
    let process_manager = ProcessManager::get()?;
    let mut process_manager_failure = process_manager.subscribe_failure()?;

    // Set non-blocking for async I/O. Early boot handshakes use the same fd
    // in blocking mode before it is moved into the async loop.
    let port_fd = port_file.as_raw_fd();
    set_nonblocking(port_fd)?;

    // A single AsyncFd tracks both readable and writable readiness.
    let async_port = AsyncFd::new(port_file)?;

    // A combined port carries full raw records; a dual-port control stream does not. Size the
    // allocation from the selected topology so combined throughput does not pay four reads per
    // default record while dual mode retains the small control-only working set.
    let mut read_buf = vec![0u8; primary_serial_read_buf_size(bulk_port.is_some())];
    // The final bootstrap read may also contain the first ordinary frame. Preserve that tail while
    // moving into the cursor-based buffer used by the bounded main-loop decoder.
    let mut serial_in_buf = BytesMut::from(boot_console.input.as_slice());
    let mut serial_out_buf = Vec::new();

    let mut state = AgentState::default();
    let mut workload = if handoff::is_pid_1() {
        WorkloadLatch::initialize()
    } else {
        WorkloadLatch::unavailable(
            "PID 1 handoff workloads are not wholly owned by agentd's cgroup",
        )
    };
    if let Some(reason) = workload.unavailable_reason() {
        eprintln!("checkpoint workload freezer unavailable: {reason}");
    }

    // Channel for session output events.
    let (mut session_tx, mut session_rx, bulk_session_rx, bulk_command_rx) =
        SessionOutputSender::split_channel();

    // Heartbeat/activity state.
    let mut activity = ActivityTracker::new();
    let (heartbeat_tx, heartbeat_rx) = watch::channel(heartbeat_snapshot(&state, &activity));
    // The liveness pulse runs on a dedicated OS thread, NOT a Tokio task. On the
    // single-threaded agent runtime a flood of exec output can monopolize the
    // executor and starve a heartbeat *task*, freezing the pulse even though the
    // agent is alive — which makes the host wrongly declare it unresponsive and
    // kill the sandbox. A plain OS thread is scheduled by the guest kernel
    // independently of the async runtime, so the pulse keeps ticking under load.
    let heartbeat_shutdown = Arc::new(AtomicBool::new(false));
    let heartbeat_control = Arc::new(heartbeat::HeartbeatControl::default());
    let heartbeat_thread = spawn_heartbeat_thread(
        heartbeat_rx,
        Arc::clone(&heartbeat_shutdown),
        Arc::clone(&heartbeat_control),
    );

    // Send core.ready with boot timing data.
    let ready_time_ns = clock::boottime_ns();
    let ready_msg = Message::with_payload(
        MessageType::Ready,
        0,
        &Ready {
            boot_time_ns,
            init_time_ns,
            ready_time_ns,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            bulk_transport: bulk_port
                .as_ref()
                .map(|port| BulkTransportReady::dual_port_v1(port.connection_id)),
            relay_lease: Some(RelayLeaseReady::range_lease_v1()),
            // Shared arenas are negotiated only on the local SDK-to-runtime hop. Agentd speaks to
            // the runtime over the guest consoles, so the runtime injects this capability later.
            local_transport: None,
            workload_transport_barrier_version: Some(WORKLOAD_TRANSPORT_BARRIER_VERSION),
        },
    )
    .map_err(|e| AgentdError::ExecSession(format!("encode ready: {e}")))?;
    codec::encode_to_buf(&ready_msg, &mut serial_out_buf)
        .map_err(|e| AgentdError::ExecSession(format!("encode ready frame: {e}")))?;
    flush_write_buf(&async_port, &mut serial_out_buf).await?;

    let (mut combined_bulk_rx, mut bulk_input, mut bulk_failure_rx, mut bulk_activity_rx) =
        match bulk_port {
            Some(port) => {
                let input = BulkInputState::new(port.file.try_clone()?)?;
                let (failure_rx, activity_rx) =
                    spawn_bulk_writer_task(port.file, bulk_session_rx, bulk_command_rx);
                (None, Some(input), Some(failure_rx), Some(activity_rx))
            }
            None => {
                session_tx.disable_bulk_scheduler();
                (Some(bulk_session_rx), None, None, None)
            }
        };
    let dual_port_active = bulk_input.is_some();
    let mut pending_bulk_inputs = VecDeque::<PendingBulkInput>::new();
    let mut bulk_input_bytes_since_snapshot = 0usize;
    let mut last_bulk_input_snapshot = Instant::now();
    let input_refunds = state.input_window.clone();
    let mut credit_deadline = None;
    let mut last_input_credit = state.input_window.credit()?;
    let mut read_budget = AgentReadBudget::default();

    // Main loop.
    'agent: loop {
        // All consumed bytes are now in persistent input buffers or destination-owned records.
        // Never yield after decoding inside read_turn: select cancellation could drop its frames.
        read_budget.yield_if_exhausted().await;
        if state.resume_output_after_flush {
            // The private Thawed reply crosses the primary lane before either ordinary writer
            // becomes eligible again. A partial old record is never abandoned by this release.
            flush_write_buf(&async_port, &mut serial_out_buf).await?;
            session_tx
                .resume_bulk_output()
                .await
                .map_err(|error| AgentdError::ExecSession(error.into()))?;
            state.resume_output_after_flush = false;
            state.output_parked = false;
        }
        if state.pending_freeze.as_ref().is_some_and(|message| {
            message.payload::<WorkloadFreeze>().is_ok_and(|request| {
                let position = state.input_window.position();
                position.bulk_bytes >= request.host_input.bulk_bytes
                    && position.bulk_frames >= request.host_input.bulk_frames
            })
        }) {
            let message = state.pending_freeze.take().expect("ready pending freeze");
            handle_message_with_charge(
                message,
                &mut state,
                &mut activity,
                &mut session_tx,
                &mut serial_out_buf,
                config,
                &mut workload,
                &heartbeat_control,
                None,
            )
            .await?;
            flush_write_buf(&async_port, &mut serial_out_buf).await?;
        }
        if !state.output_parked {
            let credit = state.input_window.credit()?;
            if input_credit_update_due(&last_input_credit, &credit) {
                encode_input_credit(credit, &mut serial_out_buf)?;
                flush_write_buf(&async_port, &mut serial_out_buf).await?;
                last_input_credit = credit;
                credit_deadline = None;
            }
        }
        // A control-lane disconnect cancels the pending acquire future at the select boundary.
        // Remove its stale record before rebuilding that future against the global budget.
        pending_bulk_inputs.retain(|pending| {
            client_incarnation_for_id(&state, pending.frame.record.id)
                == Some(pending.frame.incarnation)
        });
        let pending_bulk_admission = pending_bulk_inputs.front().map(|pending| {
            (
                Arc::clone(&pending.budget),
                pending.frame.record.payload.len(),
            )
        });
        let has_pending_bulk_admission = pending_bulk_admission.is_some();
        tokio::select! {
            _ = input_refunds.refunded(), if !state.output_parked && credit_deadline.is_none() => {
                if state.input_window.credit()? != last_input_credit {
                    credit_deadline = Some(time::Instant::now() + Duration::from_millis(5));
                }
            }

            _ = wait_input_credit_deadline(credit_deadline), if !state.output_parked => {
                credit_deadline = None;
                let credit = state.input_window.credit()?;
                if credit != last_input_credit {
                    encode_input_credit(credit, &mut serial_out_buf)?;
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                    last_input_credit = credit;
                }
            }

            (id, inherited, result) = std::future::poll_fn(|cx| poll_pending_stdin(&mut state, cx)),
                if !state.output_parked && !workload.is_frozen() => {
                if !inherited && let Err(error) = result {
                    encode_stdin_error(id, &AgentdError::Io(error), &mut serial_out_buf)?;
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
            }
            failure = process_manager_failure.changed() => {
                let error = match failure {
                    Ok(()) => process_manager_failure
                        .borrow()
                        .clone()
                        .unwrap_or_else(|| "process manager stopped without an error".to_string()),
                    Err(error) => format!("process manager failure channel closed: {error}"),
                };
                return Err(AgentdError::ExecSession(error));
            }

            Some(error) = recv_optional(&mut bulk_failure_rx) => {
                if state.output_parked {
                    return Err(AgentdError::ExecSession(format!(
                        "dedicated bulk transport failed while frozen: {error}"
                    )));
                }
                cancel_all_bulk_correlations(
                    &mut state,
                    &session_tx,
                    &mut serial_out_buf,
                    "dedicated bulk transport failed",
                )?;
                let _ = time::timeout(
                    BULK_FAILURE_FLUSH_TIMEOUT,
                    flush_write_buf(&async_port, &mut serial_out_buf),
                ).await;
                return Err(AgentdError::ExecSession(format!(
                    "dedicated bulk transport failed: {error}"
                )));
            }

            Some(output_activity) = recv_optional(&mut bulk_activity_rx) => {
                apply_raw_activity(output_activity, &mut activity);
                publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
            }

            permit = acquire_bulk_input_permit(pending_bulk_admission), if has_pending_bulk_admission => {
                let pending = pending_bulk_inputs
                    .pop_front()
                    .expect("guarded pending bulk input exists");
                let permit = match permit {
                    Ok(permit) => permit,
                    Err(error) => {
                        // The process-wide budget is never normally closed. Preserve the
                        // ownership check so a future epoch-scoped budget can cancel stale waits
                        // without allowing old bytes into a recycled correlation range.
                        if validate_bulk_client_incarnation(
                            &state,
                            pending.frame.record.id,
                            pending.frame.incarnation,
                        )? {
                            return Err(error);
                        }
                        continue;
                    }
                };
                if !validate_bulk_client_incarnation(
                    &state,
                    pending.frame.record.id,
                    pending.frame.incarnation,
                )? {
                    continue;
                }
                let payload_len = pending.frame.record.payload.len();
                let bulk_session_tx = session_tx.with_incarnation(Some(pending.frame.incarnation));
                handle_bulk_record(
                    AdmittedBulkRecord {
                        record: pending.frame.record,
                        _permit: permit,
                        _transport_charge: Some(pending.charge),
                    },
                    &mut state,
                    &mut activity,
                    &mut serial_out_buf,
                    &bulk_session_tx,
                ).await?;
                bulk_input_bytes_since_snapshot =
                    bulk_input_bytes_since_snapshot.saturating_add(payload_len);
                if bulk_input_bytes_since_snapshot >= BULK_ACTIVITY_PUBLISH_BYTES
                    || last_bulk_input_snapshot.elapsed() >= BULK_ACTIVITY_PUBLISH_INTERVAL
                {
                    publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                    bulk_input_bytes_since_snapshot = 0;
                    last_bulk_input_snapshot = Instant::now();
                }
                if !serial_out_buf.is_empty() {
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
            }

            Some(envelope) = recv_optional(&mut combined_bulk_rx), if !state.output_parked => {
                if discard_inherited_output(&mut state, &envelope, session_tx.generation()) {
                    continue;
                }
                if envelope.incarnation.is_some()
                    && client_incarnation_for_id(&state, envelope.id) != envelope.incarnation
                {
                    continue;
                }
                let SessionOutput::Bulk(output) = envelope.output else {
                    return Err(AgentdError::ExecSession(
                        "non-bulk event entered combined bulk queue".into(),
                    ));
                };
                apply_raw_activity(output.activity, &mut activity);
                if !serial_out_buf.is_empty() {
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
                write_bulk_record_async_fd(&async_port, &output.record).await?;
                publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
            }

            turn = async {
                bulk_input
                    .as_mut()
                    .expect("guarded dedicated bulk input")
                    .read_turn(&mut read_budget)
                    .await
            }, if bulk_input.is_some() && pending_bulk_inputs.is_empty() => {
                let frames = match turn {
                    Ok(frames) => frames,
                    Err(error) => {
                        cancel_all_bulk_correlations(
                            &mut state,
                            &session_tx,
                            &mut serial_out_buf,
                            "dedicated bulk transport failed",
                        )?;
                        let _ = time::timeout(
                            BULK_FAILURE_FLUSH_TIMEOUT,
                            flush_write_buf(&async_port, &mut serial_out_buf),
                        ).await;
                        return Err(AgentdError::ExecSession(format!(
                            "dedicated bulk transport failed: {error}"
                        )));
                    }
                };
                let mut capacity_deferred = false;
                if state.output_parked && !frames.is_empty() {
                    return Err(AgentdError::ExecSession("bulk input crossed the frozen transport cut".into()));
                }
                for frame in frames {
                    let charge = state.input_window.admit(
                        InputLane::Bulk, bulk_wire_bytes(&frame.record, true),
                    )?;
                    if !validate_bulk_client_incarnation(
                        &state,
                        frame.record.id,
                        frame.incarnation,
                    )? {
                        // The range has been disconnected or recycled since these bytes entered
                        // the other physical lane. They must not affect the new owner's ID.
                        continue;
                    }
                    let budget = Arc::clone(&state.bulk_input_budget);
                    if capacity_deferred {
                        pending_bulk_inputs.push_back(PendingBulkInput { frame, budget, charge });
                        continue;
                    }
                    let payload_len = frame.record.payload.len();
                    let charged = u32::try_from(payload_len).map_err(|_| {
                        AgentdError::ExecSession("bulk input payload budget overflow".into())
                    })?;
                    let permit = match Arc::clone(&budget).try_acquire_many_owned(charged) {
                        Ok(permit) => permit,
                        Err(_) if !budget.is_closed() => {
                            capacity_deferred = true;
                            pending_bulk_inputs.push_back(PendingBulkInput { frame, budget, charge });
                            continue;
                        }
                        Err(error) => {
                            return Err(AgentdError::ExecSession(format!(
                                "bulk input budget closed unexpectedly: {error}"
                            )));
                        }
                    };
                    let bulk_session_tx = session_tx.with_incarnation(Some(frame.incarnation));
                    handle_bulk_record(
                        AdmittedBulkRecord {
                            record: frame.record,
                            _permit: permit,
                            _transport_charge: Some(charge),
                        },
                        &mut state,
                        &mut activity,
                        &mut serial_out_buf,
                        &bulk_session_tx,
                    ).await?;
                    bulk_input_bytes_since_snapshot =
                        bulk_input_bytes_since_snapshot.saturating_add(payload_len);
                }
                if bulk_input_bytes_since_snapshot >= BULK_ACTIVITY_PUBLISH_BYTES
                    || last_bulk_input_snapshot.elapsed() >= BULK_ACTIVITY_PUBLISH_INTERVAL
                {
                    publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                    bulk_input_bytes_since_snapshot = 0;
                    last_bulk_input_snapshot = Instant::now();
                }
                if !serial_out_buf.is_empty() {
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
            }

            // Read from serial port.
            result = async_port.readable() => {
                let Ok(mut guard) = result else {
                    break;
                };
                let mut combined_bulk_records = 0usize;
                let mut combined_bulk_payload_bytes = 0usize;
                let mut combined_turn_exhausted = false;

                loop {
                    match guard.try_io(|inner| {
                        read_budget.read_fd(inner.get_ref().as_raw_fd(), &mut read_buf)
                    }) {
                        Ok(Ok(0)) => {
                            // EOF on serial — host disconnected.
                            if !handoff::is_pid_1() {
                                guard.clear_ready();
                                drop(guard);
                                time::sleep(Duration::from_millis(100)).await;
                                break;
                            }
                            break 'agent;
                        }
                        Ok(Ok(n)) => {
                            serial_in_buf.extend_from_slice(&read_buf[..n]);

                            // Guard against unbounded buffer growth.
                            if serial_in_buf.len() > MAX_INPUT_BUF_SIZE {
                                return Err(AgentdError::ExecSession(
                                    "serial input buffer exceeded maximum size".into(),
                                ));
                            }

                            // Try to parse complete frames. Recoverable
                            // message-level failures are reported on the same
                            // correlation ID with `core.error`; unrecoverable
                            // frame-level failures still close the agent loop.
                            loop {
                                let input_before = serial_in_buf.len();
                                if let Some(connected) =
                                        try_decode_relay_client_connected_from_bytes(&mut serial_in_buf)
                                            .map_err(|e| AgentdError::ExecSession(format!(
                                                "decode relay client lease: {e}"
                                            )))?
                                {
                                    if state.output_parked {
                                        return Err(AgentdError::ExecSession("relay lease crossed the frozen transport cut".into()));
                                    }
                                    let _charge = state.input_window.admit(
                                        InputLane::Control, input_before - serial_in_buf.len(),
                                    )?;
                                    establish_relay_client(&mut state, connected)?;
                                    continue;
                                }
                                let Some(frame) = codec::try_decode_frame_from_bytes(&mut serial_in_buf)
                                    .map_err(|e| AgentdError::ExecSession(format!("decode frame: {e}")))?
                                else {
                                    break;
                                };
                                let wire_bytes = input_before - serial_in_buf.len();
                                let DecodedFrame::Control(msg) = frame else {
                                    let DecodedFrame::Bulk(record) = frame else {
                                        unreachable!();
                                    };
                                    if dual_port_active {
                                        return Err(AgentdError::ExecSession(
                                            "raw bulk record arrived on the bound control port"
                                                .into(),
                                        ));
                                    }
                                    if state.output_parked {
                                        return Err(AgentdError::ExecSession("raw input crossed the frozen transport cut".into()));
                                    }
                                    let bulk_session_tx = session_tx.with_incarnation(
                                        client_incarnation_for_id(&state, record.id),
                                    );
                                    let payload_len = record.payload.len();
                                    let charge = state.input_window.admit(InputLane::Bulk, wire_bytes)?;
                                    let budget = Arc::clone(&state.bulk_input_budget);
                                    let permit = acquire_bulk_input_permit(Some((
                                        budget,
                                        payload_len,
                                    ))).await?;
                                    handle_bulk_record(
                                        AdmittedBulkRecord {
                                            record,
                                            _permit: permit,
                                            _transport_charge: Some(charge),
                                        },
                                        &mut state,
                                        &mut activity,
                                        &mut serial_out_buf,
                                        &bulk_session_tx,
                                    ).await?;
                                    combined_bulk_records = combined_bulk_records.saturating_add(1);
                                    combined_bulk_payload_bytes =
                                        combined_bulk_payload_bytes.saturating_add(payload_len);
                                    bulk_input_bytes_since_snapshot =
                                        bulk_input_bytes_since_snapshot.saturating_add(payload_len);
                                    if bulk_input_bytes_since_snapshot >= BULK_ACTIVITY_PUBLISH_BYTES
                                        || last_bulk_input_snapshot.elapsed()
                                            >= BULK_ACTIVITY_PUBLISH_INTERVAL
                                    {
                                        publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                                        bulk_input_bytes_since_snapshot = 0;
                                        last_bulk_input_snapshot = Instant::now();
                                    }
                                    if bulk_reader_turn_exhausted(
                                        combined_bulk_records,
                                        combined_bulk_payload_bytes,
                                    ) {
                                        // A task-level yield is insufficient here: this branch is
                                        // still inside the serial drain loop, so agent session
                                        // output (including bulk credit) cannot be selected. Finish
                                        // decoding the bytes already read, then return to the outer
                                        // select before reading another batch from the port.
                                        combined_turn_exhausted = true;
                                    }
                                    continue;
                                };
                                let charge = if private_lifecycle_message(&msg) {
                                    None
                                } else {
                                    if state.output_parked {
                                        return Err(AgentdError::ExecSession("ordinary input crossed the frozen transport cut".into()));
                                    }
                                    let lane = if msg.t.uses_workload_data_credit() {
                                        InputLane::Bulk
                                    } else {
                                        InputLane::Control
                                    };
                                    Some(state.input_window.admit(lane, wire_bytes)?)
                                };
                                if msg.flags != msg.t.flags() {
                                    let out_before = serial_out_buf.len();
                                    encode_core_error_if_supported(
                                        &msg,
                                        msg.id,
                                        CoreErrorKind::InvalidFlags,
                                        format!(
                                            "invalid flags for {}: got {}, expected {}",
                                            msg.t.as_str(),
                                            msg.flags,
                                            msg.t.flags()
                                        ),
                                        Some(msg.t.as_str().to_string()),
                                        &mut serial_out_buf,
                                    )?;
                                    record_encoded_guest_messages(
                                        &serial_out_buf,
                                        out_before,
                                        &mut activity,
                                    );
                                    publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                                    continue;
                                }

                                if message_refreshes_idle_timer(&msg.t) {
                                    activity.record_host_message();
                                    publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                                }

                                let out_before = serial_out_buf.len();
                                handle_message_with_charge(
                                    msg,
                                    &mut state,
                                    &mut activity,
                                    &mut session_tx,
                                    &mut serial_out_buf,
                                    config,
                                    &mut workload,
                                    &heartbeat_control,
                                    charge,
                                ).await?;
                                record_encoded_guest_messages(
                                    &serial_out_buf,
                                    out_before,
                                    &mut activity,
                                );
                                publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);
                            }

                            // Flush any outgoing messages.
                            if !serial_out_buf.is_empty() {
                                flush_write_buf(&async_port, &mut serial_out_buf).await?;
                            }
                            // Thawed has now crossed the wire. A host can immediately resume
                            // ordinary input, so release our parked writers at the outer-loop
                            // boundary before draining another readable batch.
                            if combined_turn_exhausted
                                || state.resume_output_after_flush
                                || read_budget.exhausted()
                            {
                                break;
                            }
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                            if read_budget.exhausted() {
                                break;
                            }
                            continue;
                        }
                        Ok(Err(_)) if !handoff::is_pid_1() => {
                            guard.clear_ready();
                            drop(guard);
                            time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_would_block) => break,
                    }
                }
            }

            // Receive output events from session reader tasks.
            Some(envelope) = session_rx.recv(), if !state.output_parked => {
                if discard_inherited_output(&mut state, &envelope, session_tx.generation()) {
                    continue;
                }
                if envelope.incarnation.is_some()
                    && client_incarnation_for_id(&state, envelope.id) != envelope.incarnation
                {
                    // Background output carries the owner captured at session creation. Dropping
                    // stale output here protects control frames as well as dedicated raw records.
                    continue;
                }
                let id = envelope.id;
                match envelope.output {
                    SessionOutput::Stdout(data) => {
                        let len = data.len();
                        let msg = Message::with_payload(MessageType::ExecStdout, id, &ExecStdout { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stdout frame: {e}")))?;
                        activity.record_guest_message();
                        activity.add_exec_output_bytes(len);
                    }
                    SessionOutput::Stderr(data) => {
                        let len = data.len();
                        let msg = Message::with_payload(MessageType::ExecStderr, id, &ExecStderr { data })
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode stderr frame: {e}")))?;
                        activity.record_guest_message();
                        activity.add_exec_output_bytes(len);
                    }
                    SessionOutput::Exited(code) => {
                        let msg = Message::with_payload(MessageType::ExecExited, id, &ExecExited { code })
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited: {e}")))?;
                        codec::encode_to_buf(&msg, &mut serial_out_buf)
                            .map_err(|e| AgentdError::ExecSession(format!("encode exited frame: {e}")))?;
                        state.sessions.remove(&id);
                        activity.record_guest_message();
                    }
                    SessionOutput::Raw(output) => {
                        apply_raw_activity(output.activity, &mut activity);
                        let completion = output.completion;
                        complete_raw_session(
                            id,
                            completion,
                            &mut state.read_sessions,
                            &mut state.tcp_sessions,
                        );
                        if matches!(completion, Some(RawSessionCompletion::FsWrite))
                            && let Some(worker) = state.bulk_write_workers.remove(&id)
                        {
                            worker.task.abort();
                        }
                        if completion.is_some() {
                            clear_bulk_receive_state(&mut state, id);
                        }
                        // The producer already owns an encoded frame. Write from that allocation
                        // directly so multi-megabyte FS/TCP frames are not copied into a second
                        // serial staging buffer.
                        if !serial_out_buf.is_empty() {
                            flush_write_buf(&async_port, &mut serial_out_buf).await?;
                        }
                        if !output.frame.is_empty() {
                            write_all_async_fd(&async_port, &output.frame).await?;
                        }
                    }
                    SessionOutput::Bulk(output) => {
                        apply_raw_activity(output.activity, &mut activity);
                        if !serial_out_buf.is_empty() {
                            flush_write_buf(&async_port, &mut serial_out_buf).await?;
                        }
                        write_bulk_record_async_fd(&async_port, &output.record).await?;
                    }
                }
                publish_heartbeat_snapshot(&heartbeat_tx, &state, &activity);

                if !serial_out_buf.is_empty() {
                    flush_write_buf(&async_port, &mut serial_out_buf).await?;
                }
            }
        }
    }

    heartbeat_shutdown.store(true, Ordering::Relaxed);
    let _ = heartbeat_thread.join();

    Ok(())
}

/// Start the dedicated-lane output actor; input stays fused into the main control actor.
fn spawn_bulk_writer_task(
    writer_file: File,
    output_rx: tokio::sync::mpsc::Receiver<SessionOutputEnvelope>,
    command_rx: tokio::sync::mpsc::Receiver<BulkOutputCommand>,
) -> (
    tokio::sync::mpsc::Receiver<String>,
    tokio::sync::mpsc::Receiver<RawActivity>,
) {
    let (failure_tx, failure_rx) = tokio::sync::mpsc::channel(1);
    let (activity_tx, activity_rx) = tokio::sync::mpsc::channel(128);

    tokio::spawn(async move {
        if let Err(error) = bulk_writer_task(writer_file, output_rx, command_rx, activity_tx).await
        {
            let _ = failure_tx.send(error.to_string()).await;
        }
    });

    (failure_rx, activity_rx)
}

/// Select the primary port's read working set from whether bulk has its own physical lane.
fn primary_serial_read_buf_size(has_dedicated_bulk_port: bool) -> usize {
    if has_dedicated_bulk_port {
        CONTROL_SERIAL_READ_BUF_SIZE
    } else {
        COMBINED_SERIAL_READ_BUF_SIZE
    }
}

/// Bound one raw-input scheduling turn so a single-thread guest can run the destination worker.
fn bulk_reader_turn_exhausted(records: usize, payload_bytes: usize) -> bool {
    records >= BULK_READER_MAX_RECORDS_PER_TURN || payload_bytes >= BULK_READER_MAX_BYTES_PER_TURN
}

/// Receive from an optional channel without making combined mode spin.
async fn recv_optional<T>(receiver: &mut Option<tokio::sync::mpsc::Receiver<T>>) -> Option<T> {
    let Some(active) = receiver.as_mut() else {
        return std::future::pending().await;
    };
    match active.recv().await {
        Some(value) => Some(value),
        None => {
            // Disable a closed optional branch. Returning `None` immediately on every select-loop
            // iteration would turn a failed worker into a one-vCPU busy loop while its companion
            // failure channel is still trying to report the real error.
            *receiver = None;
            std::future::pending().await
        }
    }
}

/// Schedule guest-to-host records fairly by correlation before writing the bulk port.
async fn bulk_writer_task(
    file: File,
    mut output_rx: tokio::sync::mpsc::Receiver<SessionOutputEnvelope>,
    mut command_rx: tokio::sync::mpsc::Receiver<BulkOutputCommand>,
    activity_tx: tokio::sync::mpsc::Sender<RawActivity>,
) -> AgentdResult<()> {
    let async_port = AsyncFd::new(file)?;
    let mut generation = 0;
    let mut flows = HashMap::<(ClientIncarnation, u32), BulkWriteFlow>::new();
    let mut active = VecDeque::<(ClientIncarnation, u32)>::new();
    let mut retired = HashMap::<ClientIncarnation, Vec<u64>>::new();
    let mut retiring_incarnations = HashSet::<ClientIncarnation>::new();
    let mut pending_activity = RawActivity::default();
    let mut transport = BulkOutputPosition::default();

    loop {
        let mut cleanups = Vec::new();
        tokio::select! {
            biased;
            Some(command) = command_rx.recv() => {
                cleanups.push(apply_bulk_output_command(
                    command,
                    &mut generation,
                    &mut flows,
                    &mut active,
                    &mut retired,
                    &mut retiring_incarnations,
                    &mut transport,
                )?);
            }
            Some(envelope) = output_rx.recv(), if !transport.parked => {
                enqueue_bulk_output(
                    envelope,
                    generation,
                    &mut flows,
                    &mut active,
                    &retired,
                    &retiring_incarnations,
                )?;
            }
            else => break,
        }
        while let Ok(command) = command_rx.try_recv() {
            cleanups.push(apply_bulk_output_command(
                command,
                &mut generation,
                &mut flows,
                &mut active,
                &mut retired,
                &mut retiring_incarnations,
                &mut transport,
            )?);
        }
        while let Ok(envelope) = output_rx.try_recv() {
            enqueue_bulk_output(
                envelope,
                generation,
                &mut flows,
                &mut active,
                &retired,
                &retiring_incarnations,
            )?;
        }
        complete_bulk_output_cleanups(cleanups, &mut retired, &mut retiring_incarnations);

        while !transport.parked && !active.is_empty() {
            let round_len = active.len();
            let quantum = if round_len == 1 {
                BULK_SCHEDULER_MAX_BURST
            } else {
                BULK_SCHEDULER_QUANTUM
            };
            for _ in 0..round_len {
                if transport.parked || active.is_empty() {
                    break;
                }
                let key = active.pop_front().expect("active flow exists");
                if let Some(flow) = flows.get_mut(&key) {
                    flow.deficit = flow
                        .deficit
                        .saturating_add(quantum)
                        .min(BULK_SCHEDULER_MAX_BURST);
                }

                let mut burst = 0usize;
                loop {
                    let next_len = flows
                        .get(&key)
                        .and_then(|flow| flow.queue.front())
                        .map(bulk_envelope_payload_len)
                        .transpose()?
                        .unwrap_or(0);
                    let can_send = flows.get(&key).is_some_and(|flow| {
                        next_len != 0
                            && next_len <= flow.deficit
                            && burst.saturating_add(next_len) <= BULK_SCHEDULER_MAX_BURST
                    });
                    if !can_send {
                        break;
                    }

                    let envelope = {
                        let flow = flows.get_mut(&key).expect("scheduled flow exists");
                        let envelope = flow.queue.pop_front().expect("scheduled record exists");
                        flow.queued_bytes = flow.queued_bytes.saturating_sub(next_len);
                        flow.deficit = flow.deficit.saturating_sub(next_len);
                        envelope
                    };
                    let incarnation = envelope.incarnation.ok_or_else(|| {
                        AgentdError::ExecSession(
                            "dedicated bulk output is missing client incarnation".into(),
                        )
                    })?;
                    let SessionOutput::Bulk(output) = envelope.output else {
                        unreachable!("bulk scheduler accepted a non-bulk event");
                    };
                    let output_activity = output.activity;
                    write_incarnated_bulk_record_async_fd(&async_port, incarnation, &output.record)
                        .await?;
                    transport.wire_bytes = transport
                        .wire_bytes
                        .checked_add(bulk_wire_bytes(&output.record, true) as u64)
                        .ok_or_else(|| {
                            AgentdError::ExecSession("bulk output counter exhausted".into())
                        })?;
                    pending_activity.guest_messages = pending_activity
                        .guest_messages
                        .saturating_add(output_activity.guest_messages);
                    pending_activity.fs_bytes = pending_activity
                        .fs_bytes
                        .saturating_add(output_activity.fs_bytes);
                    pending_activity.tcp_bytes = pending_activity
                        .tcp_bytes
                        .saturating_add(output_activity.tcp_bytes);
                    if pending_activity
                        .fs_bytes
                        .saturating_add(pending_activity.tcp_bytes)
                        >= BULK_ACTIVITY_PUBLISH_BYTES
                    {
                        publish_bulk_activity(&activity_tx, &mut pending_activity)?;
                    }
                    burst = burst.saturating_add(next_len);
                    // Lifecycle commands cut only between complete wire records. In particular,
                    // never wait for the rest of this flow's burst before acknowledging Park.
                    let mut cleanups = Vec::new();
                    while let Ok(command) = command_rx.try_recv() {
                        cleanups.push(apply_bulk_output_command(
                            command,
                            &mut generation,
                            &mut flows,
                            &mut active,
                            &mut retired,
                            &mut retiring_incarnations,
                            &mut transport,
                        )?);
                    }
                    while let Ok(envelope) = output_rx.try_recv() {
                        enqueue_bulk_output(
                            envelope,
                            generation,
                            &mut flows,
                            &mut active,
                            &retired,
                            &retiring_incarnations,
                        )?;
                    }
                    complete_bulk_output_cleanups(
                        cleanups,
                        &mut retired,
                        &mut retiring_incarnations,
                    );
                    if transport.parked {
                        break;
                    }
                }

                if flows.get(&key).is_some_and(|flow| flow.queue.is_empty()) {
                    flows.remove(&key);
                } else if flows.contains_key(&key) && !active.contains(&key) {
                    active.push_back(key);
                }
            }

            let mut cleanups = Vec::new();
            while let Ok(command) = command_rx.try_recv() {
                cleanups.push(apply_bulk_output_command(
                    command,
                    &mut generation,
                    &mut flows,
                    &mut active,
                    &mut retired,
                    &mut retiring_incarnations,
                    &mut transport,
                )?);
            }
            while let Ok(envelope) = output_rx.try_recv() {
                enqueue_bulk_output(
                    envelope,
                    generation,
                    &mut flows,
                    &mut active,
                    &retired,
                    &retiring_incarnations,
                )?;
            }
            complete_bulk_output_cleanups(cleanups, &mut retired, &mut retiring_incarnations);
            if active.is_empty() && pending_activity.guest_messages != 0 {
                publish_bulk_activity(&activity_tx, &mut pending_activity)?;
            }
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

/// Activity must never prevent a restore command from reaching the scheduler.
fn publish_bulk_activity(
    sender: &tokio::sync::mpsc::Sender<RawActivity>,
    pending: &mut RawActivity,
) -> AgentdResult<()> {
    match sender.try_send(std::mem::take(pending)) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(activity)) => {
            *pending = activity;
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(AgentdError::ExecSession(
            "dedicated bulk activity consumer stopped".into(),
        )),
    }
}

fn apply_bulk_output_command(
    command: BulkOutputCommand,
    generation: &mut u64,
    flows: &mut HashMap<(ClientIncarnation, u32), BulkWriteFlow>,
    active: &mut VecDeque<(ClientIncarnation, u32)>,
    retired: &mut HashMap<ClientIncarnation, Vec<u64>>,
    retiring_incarnations: &mut HashSet<ClientIncarnation>,
    transport: &mut BulkOutputPosition,
) -> AgentdResult<BulkOutputCleanup> {
    match command {
        BulkOutputCommand::Park { completion } => {
            transport.parked = true;
            Ok(BulkOutputCleanup::Park {
                completion,
                wire_bytes: transport.wire_bytes,
            })
        }
        BulkOutputCommand::Resume { completion } => {
            transport.parked = false;
            Ok(BulkOutputCleanup::Flow(completion))
        }
        BulkOutputCommand::Restore {
            generation: next,
            completion,
        } => {
            *generation = next;
            flows.clear();
            active.clear();
            retired.clear();
            retiring_incarnations.clear();
            Ok(BulkOutputCleanup::Flow(completion))
        }
        BulkOutputCommand::DropFlow {
            incarnation,
            id,
            completion,
        } => {
            let key = (incarnation, id);
            flows.remove(&key);
            active.retain(|active_key| *active_key != key);
            retire_bulk_output(retired, incarnation, id)?;
            Ok(BulkOutputCleanup::Flow(completion))
        }
        BulkOutputCommand::DropIncarnation {
            incarnation,
            completion,
        } => {
            flows.retain(|(owner, _), _| *owner != incarnation);
            active.retain(|(owner, _)| *owner != incarnation);
            retiring_incarnations.insert(incarnation);
            Ok(BulkOutputCleanup::Incarnation {
                incarnation,
                completion,
            })
        }
    }
}

/// Complete lifecycle cuts only after the data receiver has been drained through its tombstones.
fn complete_bulk_output_cleanups(
    cleanups: Vec<BulkOutputCleanup>,
    retired: &mut HashMap<ClientIncarnation, Vec<u64>>,
    retiring_incarnations: &mut HashSet<ClientIncarnation>,
) {
    for cleanup in cleanups {
        match cleanup {
            BulkOutputCleanup::Park {
                completion,
                wire_bytes,
            } => {
                let _ = completion.send(wire_bytes);
            }
            BulkOutputCleanup::Flow(completion) => {
                let _ = completion.send(());
            }
            BulkOutputCleanup::Incarnation {
                incarnation,
                completion,
            } => {
                retired.remove(&incarnation);
                retiring_incarnations.remove(&incarnation);
                let _ = completion.send(());
            }
        }
    }
}

fn enqueue_bulk_output(
    envelope: SessionOutputEnvelope,
    generation: u64,
    flows: &mut HashMap<(ClientIncarnation, u32), BulkWriteFlow>,
    active: &mut VecDeque<(ClientIncarnation, u32)>,
    retired: &HashMap<ClientIncarnation, Vec<u64>>,
    retiring_incarnations: &HashSet<ClientIncarnation>,
) -> AgentdResult<()> {
    if envelope.generation != generation {
        return Ok(());
    }
    let id = envelope.id;
    let incarnation = envelope.incarnation.ok_or_else(|| {
        AgentdError::ExecSession("dedicated bulk output is missing client incarnation".into())
    })?;
    let payload_len = bulk_envelope_payload_len(&envelope)?;
    if id == 0 {
        return Err(AgentdError::ExecSession(
            "bulk record cannot use correlation ID zero".into(),
        ));
    }
    if payload_len == 0 || payload_len > MAX_BULK_RECORD_PAYLOAD as usize {
        return Err(AgentdError::ExecSession(format!(
            "bulk output payload {payload_len} exceeds schedulable maximum {MAX_BULK_RECORD_PAYLOAD}"
        )));
    }

    let key = (incarnation, id);
    if retiring_incarnations.contains(&incarnation)
        || bulk_output_is_retired(retired, incarnation, id)
    {
        // A producer can race cancellation after the lifecycle command overtakes the data queue.
        // Retaining the owner-scoped tombstone makes that late record release its permit here.
        return Ok(());
    }
    if !flows.contains_key(&key) {
        let client_flows = flows
            .keys()
            .filter(|(owner, _)| *owner == incarnation)
            .count();
        if client_flows >= BULK_SCHEDULER_MAX_FLOWS_PER_CLIENT {
            return Err(AgentdError::ExecSession(format!(
                "relay client exceeded active bulk-flow limit for correlation {id}"
            )));
        }
        flows.insert(
            key,
            BulkWriteFlow {
                queue: VecDeque::new(),
                queued_bytes: 0,
                deficit: 0,
            },
        );
        active.push_back(key);
    }

    let flow = flows.get_mut(&key).expect("newly inserted flow exists");
    let queued_bytes = flow
        .queued_bytes
        .checked_add(payload_len)
        .ok_or_else(|| AgentdError::ExecSession("bulk flow byte budget overflow".into()))?;
    if queued_bytes > BULK_SCHEDULER_FLOW_CAPACITY {
        return Err(AgentdError::ExecSession(format!(
            "bulk flow {id} exceeded queued byte budget"
        )));
    }
    flow.queued_bytes = queued_bytes;
    flow.queue.push_back(envelope);
    Ok(())
}

fn bulk_envelope_payload_len(envelope: &SessionOutputEnvelope) -> AgentdResult<usize> {
    match &envelope.output {
        SessionOutput::Bulk(output) => Ok(output.record.payload.len()),
        _ => Err(AgentdError::ExecSession(
            "non-bulk event entered dedicated bulk scheduler".into(),
        )),
    }
}

/// Discover and bind the dedicated bulk port when the internal boot hint requests it.
pub fn open_and_bind_bulk_port() -> AgentdResult<Option<BoundBulkPort>> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    if !cmdline_requests_dual_port(&cmdline) {
        return Ok(None);
    }

    let deadline = Instant::now() + Duration::from_secs(BULK_BINDING_TIMEOUT_SECS);
    let port_path = loop {
        match serial::find_serial_port(AGENT_BULK_PORT_NAME) {
            Ok(path) => break path,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    let file = OpenOptions::new().read(true).write(true).open(port_path)?;
    let fd = file.as_raw_fd();
    set_nonblocking(fd)?;

    let connection_id = random_connection_id()?;
    write_all_to_fd(fd, &encode_bulk_hello(connection_id), deadline)?;

    let mut ack = [0u8; BULK_BINDING_SIZE];
    read_exact_from_fd(fd, &mut ack, deadline, "bulk binding acknowledgement")?;
    decode_bulk_ack(&ack, connection_id)
        .map_err(|error| AgentdError::ExecSession(format!("bind agent-bulk: {error}")))?;

    Ok(Some(BoundBulkPort {
        file,
        connection_id,
    }))
}

/// Opens the agent virtio-serial port once for early boot handshakes and the agent loop.
pub fn open_serial_port() -> AgentdResult<File> {
    // Discover serial port.
    let port_path = serial::find_serial_port(AGENT_PORT_NAME)?;

    // Open the port once with read+write. Virtio-console multiport devices
    // only allow a single open; a second open returns EBUSY.
    Ok(OpenOptions::new().read(true).write(true).open(&port_path)?)
}

/// Receive and validate the first host-to-guest bootstrap frame.
pub fn receive_bootstrap(port_file: &File) -> AgentdResult<(GuestBootstrap, BootConsoleState)> {
    let fd = port_file.as_raw_fd();
    set_nonblocking(fd)?;
    let deadline = init_ack_deadline();
    let mut state = BootConsoleState::default();
    let msg = read_boot_message(fd, &mut state, deadline, "guest bootstrap")?;
    let bootstrap = decode_bootstrap_message(msg)?;
    Ok((bootstrap, state))
}

fn decode_bootstrap_message(msg: Message) -> AgentdResult<GuestBootstrap> {
    if msg.id != 0 || msg.flags != 0 {
        return Err(AgentdError::Config(format!(
            "guest bootstrap requires id=0 and flags=0, got id={} flags={}",
            msg.id, msg.flags
        )));
    }
    if msg.t != MessageType::Bootstrap {
        return Err(AgentdError::Config(format!(
            "expected core.bootstrap as first console frame, got {}",
            msg.t.as_str()
        )));
    }
    let min_version = MessageType::Bootstrap.min_protocol_version();
    if msg.v < min_version {
        return Err(AgentdError::Config(format!(
            "guest bootstrap requires protocol generation {min_version} or newer, got {}",
            msg.v
        )));
    }

    msg.payload::<GuestBootstrap>()
        .map_err(|e| AgentdError::Config(format!("decode guest bootstrap payload: {e}")))
}

/// Reports init-time guest context to the host and waits for an acknowledgement.
pub fn report_init_context(
    port_file: &File,
    boot_console: &mut BootConsoleState,
    default_user: Option<&str>,
) -> AgentdResult<()> {
    let (uid, gid) = resolve_default_user(default_user)?;
    let deadline = init_ack_deadline();
    let fd = port_file.as_raw_fd();
    set_nonblocking(fd)?;

    let msg = Message::with_payload(
        MessageType::InitResolved,
        0,
        &InitResolved {
            default_user: ResolvedUser { uid, gid },
        },
    )
    .map_err(|e| AgentdError::ExecSession(format!("encode init context: {e}")))?;

    let mut out = Vec::new();
    codec::encode_to_buf(&msg, &mut out)
        .map_err(|e| AgentdError::ExecSession(format!("encode init context frame: {e}")))?;
    write_all_to_fd(fd, &out, deadline)?;
    wait_for_init_ack(fd, boot_console, deadline)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn ensure_fs_bulk_write_worker(
    id: u32,
    state: &mut AgentState,
    session_tx: &SessionOutputSender,
) -> Result<(), String> {
    if state.bulk_write_workers.contains_key(&id) {
        return Ok(());
    }

    let session = state
        .write_sessions
        .remove(&id)
        .ok_or_else(|| format!("unknown filesystem write session: {id}"))?;
    if !session.is_bulk() {
        state.write_sessions.insert(id, session);
        return Err("raw bulk record sent to a generation-6 filesystem write".into());
    }

    let (records, record_rx) = tokio::sync::mpsc::channel(FS_BULK_INPUT_ITEM_CAPACITY);
    // Finish is a lifecycle cut, not another data record. Its dedicated slot cannot be consumed by
    // a legal full 8 MiB data window.
    let (finish, finish_rx) = tokio::sync::mpsc::channel(1);
    let output = session_tx.clone();
    let task = tokio::spawn(run_fs_bulk_write_worker(
        id, session, record_rx, finish_rx, output,
    ));
    state.bulk_write_workers.insert(
        id,
        FsBulkWriteWorker {
            records,
            finish,
            task,
        },
    );
    Ok(())
}

fn enqueue_fs_bulk_record(
    id: u32,
    record: AdmittedBulkRecord,
    state: &mut AgentState,
    session_tx: &SessionOutputSender,
) -> Result<(), String> {
    ensure_fs_bulk_write_worker(id, state, session_tx)?;
    let result = state
        .bulk_write_workers
        .get(&id)
        .expect("filesystem bulk worker was just established")
        .records
        .try_send(record)
        .map_err(|error| format!("filesystem bulk input queue is unavailable: {error}"));
    if result.is_err()
        && let Some(worker) = state.bulk_write_workers.remove(&id)
    {
        worker.task.abort();
    }
    result
}

fn finish_fs_bulk_write(
    id: u32,
    finish: BulkFinish,
    state: &mut AgentState,
    session_tx: &SessionOutputSender,
) -> Result<(), String> {
    ensure_fs_bulk_write_worker(id, state, session_tx)?;
    let result = state
        .bulk_write_workers
        .get(&id)
        .expect("filesystem bulk worker was just established")
        .finish
        .try_send(finish)
        .map_err(|error| format!("filesystem bulk finish path is unavailable: {error}"));
    if result.is_err()
        && let Some(worker) = state.bulk_write_workers.remove(&id)
    {
        worker.task.abort();
    }
    result
}

async fn run_fs_bulk_write_worker(
    id: u32,
    mut session: FsWriteSession,
    mut record_rx: tokio::sync::mpsc::Receiver<AdmittedBulkRecord>,
    mut finish_rx: tokio::sync::mpsc::Receiver<BulkFinish>,
    output_tx: SessionOutputSender,
) {
    let mut pending_finish = None;
    let mut finish_open = true;
    let mut received_offset = 0u64;
    let mut pending_activity_bytes = 0usize;
    let mut pending_record = None;

    loop {
        let record = if pending_record.is_some() {
            pending_record.take()
        } else {
            tokio::select! {
                biased;
                finish = finish_rx.recv(), if pending_finish.is_none() && finish_open => {
                    match finish {
                        Some(finish) => pending_finish = Some(finish),
                        None => finish_open = false,
                    }
                    None
                }
                record = record_rx.recv() => record,
            }
        };

        let Some(record) = record else {
            if pending_finish
                .as_ref()
                .is_some_and(|finish| finish.final_offset <= received_offset)
            {
                let finish = pending_finish
                    .take()
                    .expect("checked pending finish exists");
                let mut frame = Vec::new();
                if let Err(error) =
                    fs::handle_fs_bulk_finish(id, finish, &mut session, &mut frame).await
                    && encode_bulk_fs_failure(id, error, &mut frame).is_err()
                {
                    return;
                }
                let activity = RawActivity {
                    guest_messages: 1,
                    fs_bytes: std::mem::take(&mut pending_activity_bytes),
                    ..RawActivity::default()
                };
                let output = crate::session::RawSessionOutput::new(
                    frame,
                    activity,
                    Some(RawSessionCompletion::FsWrite),
                );
                let _ = output_tx.send(id, SessionOutput::Raw(output)).await;
                return;
            }
            if record_rx.is_closed() {
                return;
            }
            continue;
        };

        // Drain only records already admitted to this flow. Waiting for a larger batch would add
        // latency and could deadlock at a credit boundary; the next input scheduling turn will
        // naturally form the next batch.
        let mut records = Vec::with_capacity(
            FS_BULK_WRITE_COALESCE_BYTES.div_ceil(DEFAULT_FILESYSTEM_BULK_RECORD_PAYLOAD as usize),
        );
        let mut retained_permits = Vec::with_capacity(records.capacity());
        let mut payload_len = record.record().payload.len();
        let (record, permit) = record.into_parts();
        records.push(record);
        retained_permits.push(permit);
        while payload_len < FS_BULK_WRITE_COALESCE_BYTES {
            match record_rx.try_recv() {
                Ok(record) => {
                    let next_len = payload_len.saturating_add(record.record().payload.len());
                    if next_len > FS_BULK_WRITE_COALESCE_BYTES {
                        pending_record = Some(record);
                        break;
                    }
                    let (record, permit) = record.into_parts();
                    payload_len = next_len;
                    records.push(record);
                    retained_permits.push(permit);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let mut frame = Vec::new();
        let last_record = records
            .last()
            .expect("filesystem bulk batch contains its initial record");
        let record_end = last_record
            .offset
            .saturating_add(last_record.payload.len() as u64);
        let mut completed =
            match fs::handle_fs_bulk_records(id, &records, &mut session, &mut frame).await {
                Ok(completed) => {
                    if !completed {
                        received_offset = record_end;
                        pending_activity_bytes = pending_activity_bytes.saturating_add(payload_len);
                    }
                    completed
                }
                Err(error) => {
                    if encode_bulk_fs_failure(id, error, &mut frame).is_err() {
                        return;
                    }
                    true
                }
            };
        // Filesystem effects have consumed every payload in this batch. Release aggregate input
        // capacity before potentially waiting to publish credit or heartbeat output.
        drop(retained_permits);

        if !completed
            && pending_finish
                .as_ref()
                .is_some_and(|finish| finish.final_offset <= received_offset)
        {
            let finish = pending_finish
                .take()
                .expect("checked pending finish exists");
            completed = match fs::handle_fs_bulk_finish(id, finish, &mut session, &mut frame).await
            {
                Ok(completed) => completed,
                Err(error) => {
                    if encode_bulk_fs_failure(id, error, &mut frame).is_err() {
                        return;
                    }
                    true
                }
            };
        }

        // Credits and terminal results already need an outward event. Pure byte accounting is
        // coalesced so a successful 256 KiB record does not make a second trip through the agent
        // main loop solely to update heartbeat counters.
        if frame.is_empty() && pending_activity_bytes < FS_ACTIVITY_BATCH_BYTES && !completed {
            continue;
        }
        let activity = RawActivity {
            guest_messages: usize::from(!frame.is_empty()),
            fs_bytes: std::mem::take(&mut pending_activity_bytes),
            ..RawActivity::default()
        };
        let completion = completed.then_some(RawSessionCompletion::FsWrite);
        let output = crate::session::RawSessionOutput::new(frame, activity, completion);
        if !output_tx.send(id, SessionOutput::Raw(output)).await || completed {
            return;
        }
    }
}

/// Handles a single incoming message from the host.
async fn handle_bulk_record(
    record: AdmittedBulkRecord,
    state: &mut AgentState,
    activity: &mut ActivityTracker,
    out_buf: &mut Vec<u8>,
    session_tx: &SessionOutputSender,
) -> AgentdResult<()> {
    activity.record_host_message();
    let id = record.record().id;
    let record_end = record
        .record()
        .offset
        .checked_add(record.record().payload.len() as u64)
        .ok_or_else(|| AgentdError::ExecSession("bulk record offset overflow".into()))?;
    let record_payload_len = record.record().payload.len();
    let kind = record.record().kind;
    let flow = record.record().flow;
    let mut accepted = false;
    match kind {
        BulkKind::Filesystem => {
            if flow != BulkFlow::HostToGuest {
                encode_bulk_fs_failure(
                    id,
                    "host sent a filesystem record in the guest-to-host flow".into(),
                    out_buf,
                )?;
                cancel_bulk_correlation(id, BulkKind::Filesystem, state, session_tx);
                return Ok(());
            }

            if let Err(error) = enqueue_fs_bulk_record(id, record, state, session_tx) {
                encode_bulk_fs_failure(id, error, out_buf)?;
                cancel_bulk_correlation(id, BulkKind::Filesystem, state, session_tx);
            } else {
                accepted = true;
            }
        }
        BulkKind::Tcp => {
            if flow != BulkFlow::HostToGuest {
                encode_bulk_tcp_failure(
                    id,
                    "host sent a TCP record in the guest-to-host flow".into(),
                    out_buf,
                )?;
                cancel_bulk_correlation(id, BulkKind::Tcp, state, session_tx);
                return Ok(());
            }
            let result = match state.tcp_sessions.get(&id) {
                Some(session) => session.write_bulk(record).await,
                None => Err(format!("unknown TCP session: {id}")),
            };
            if let Err(error) = result {
                encode_bulk_tcp_failure(id, error, out_buf)?;
                cancel_bulk_correlation(id, BulkKind::Tcp, state, session_tx);
            } else {
                accepted = true;
                activity.add_tcp_bytes(record_payload_len);
            }
        }
    }
    if accepted {
        state.bulk_received_offsets.insert(id, record_end);
        if state
            .pending_bulk_finishes
            .get(&id)
            .is_some_and(|finish| finish.final_offset <= record_end)
        {
            let finish = state
                .pending_bulk_finishes
                .remove(&id)
                .expect("checked pending finish exists");
            dispatch_bulk_finish(id, finish, state, out_buf, session_tx).await?;
        }
    }
    Ok(())
}

/// Apply an exact host-to-guest end marker after all raw records through its offset arrived.
async fn dispatch_bulk_finish(
    id: u32,
    finish: BulkFinish,
    state: &mut AgentState,
    out_buf: &mut Vec<u8>,
    session_tx: &SessionOutputSender,
) -> AgentdResult<()> {
    match finish.kind {
        BulkKind::Filesystem => {
            if let Err(error) = finish_fs_bulk_write(id, finish, state, session_tx) {
                encode_bulk_fs_failure(id, error, out_buf)?;
                cancel_bulk_correlation(id, BulkKind::Filesystem, state, session_tx);
            }
        }
        BulkKind::Tcp => {
            let result = match state.tcp_sessions.get(&id) {
                Some(session) => session.finish_bulk(finish).await,
                None => Err(format!("unknown TCP session: {id}")),
            };
            if let Err(error) = result {
                encode_bulk_tcp_failure(id, error, out_buf)?;
                if let Some(session) = state.tcp_sessions.remove(&id) {
                    session.close();
                }
            }
        }
    }
    clear_bulk_receive_state(state, id);
    Ok(())
}

/// Return whether the finish belongs to a live host-to-guest raw receiver.
fn has_bulk_receive_session(state: &AgentState, id: u32, kind: BulkKind) -> bool {
    match kind {
        BulkKind::Filesystem => {
            state
                .write_sessions
                .get(&id)
                .is_some_and(FsWriteSession::is_bulk)
                || state.bulk_write_workers.contains_key(&id)
        }
        BulkKind::Tcp => state.tcp_sessions.get(&id).is_some_and(TcpSession::is_bulk),
    }
}

/// Remove offset/finish state after a correlation reaches any terminal path.
fn clear_bulk_receive_state(state: &mut AgentState, id: u32) {
    state.bulk_received_offsets.remove(&id);
    state.pending_bulk_finishes.remove(&id);
}

/// Cancel every operation resource owned by one bulk correlation.
fn cancel_bulk_correlation(
    id: u32,
    kind: BulkKind,
    state: &mut AgentState,
    session_tx: &SessionOutputSender,
) {
    let owner_tx = session_tx.with_incarnation(client_incarnation_for_id(state, id));
    // Stop every producer before publishing the scheduler cut. Any send that completed before
    // teardown is already bounded in the scheduler input queue; an in-progress send is cancelled
    // with its producer task and cannot appear after the cleanup acknowledgement.
    match kind {
        BulkKind::Filesystem => {
            state.write_sessions.remove(&id);
            if let Some(worker) = state.bulk_write_workers.remove(&id) {
                worker.task.abort();
            }
            if let Some(session) = state.read_sessions.remove(&id) {
                session.abort();
            }
        }
        BulkKind::Tcp => {
            if let Some(session) = state.tcp_sessions.remove(&id) {
                session.close();
            }
        }
    }
    clear_bulk_receive_state(state, id);
    if let Err(error) = owner_tx.drop_bulk_flow(id) {
        eprintln!("agentd: failed to purge cancelled bulk output id={id}: {error}");
    }
}

fn cancel_all_bulk_correlations(
    state: &mut AgentState,
    session_tx: &SessionOutputSender,
    out_buf: &mut Vec<u8>,
    message: &str,
) -> AgentdResult<()> {
    let mut correlations = HashMap::<u32, BulkKind>::new();
    correlations.extend(
        state
            .read_sessions
            .iter()
            .filter(|(_, session)| session.is_bulk())
            .map(|(id, _)| (*id, BulkKind::Filesystem)),
    );
    correlations.extend(
        state
            .write_sessions
            .iter()
            .filter(|(_, session)| session.is_bulk())
            .map(|(id, _)| (*id, BulkKind::Filesystem)),
    );
    correlations.extend(
        state
            .bulk_write_workers
            .keys()
            .map(|id| (*id, BulkKind::Filesystem)),
    );
    correlations.extend(
        state
            .tcp_sessions
            .iter()
            .filter(|(_, session)| session.is_bulk())
            .map(|(id, _)| (*id, BulkKind::Tcp)),
    );

    for (id, kind) in correlations {
        encode_bulk_cancel(
            id,
            kind,
            BulkCancelReason::TransportFailure,
            message.to_string(),
            out_buf,
        )?;
        cancel_bulk_correlation(id, kind, state, session_tx);
        encode_bulk_terminal_failure(id, kind, message.to_string(), out_buf)?;
    }
    Ok(())
}

/// Release reorder metadata when the relay recycles an SDK client's ID range.
fn clear_bulk_receive_range(state: &mut AgentState, id_start: u32, id_end_exclusive: u32) {
    state
        .bulk_received_offsets
        .retain(|id, _| *id < id_start || *id >= id_end_exclusive);
    state
        .pending_bulk_finishes
        .retain(|id, _| *id < id_start || *id >= id_end_exclusive);
}

fn client_incarnation_for_id(state: &AgentState, id: u32) -> Option<ClientIncarnation> {
    relay_client_slot(id).and_then(|slot| state.client_incarnations.get(&slot).copied())
}

fn bulk_output_retired_bit(id: u32) -> Option<(usize, u64)> {
    let slot = relay_client_slot(id)?;
    let (id_start, _) = relay_client_id_range(slot)?;
    let local = usize::try_from(id.checked_sub(id_start)?).ok()?;
    Some((
        local / u64::BITS as usize,
        1u64 << (local % u64::BITS as usize),
    ))
}

fn bulk_output_is_retired(
    retired: &HashMap<ClientIncarnation, Vec<u64>>,
    incarnation: ClientIncarnation,
    id: u32,
) -> bool {
    let Some((word, mask)) = bulk_output_retired_bit(id) else {
        return false;
    };
    retired
        .get(&incarnation)
        .and_then(|bitmap| bitmap.get(word))
        .is_some_and(|bits| bits & mask != 0)
}

fn retire_bulk_output(
    retired: &mut HashMap<ClientIncarnation, Vec<u64>>,
    incarnation: ClientIncarnation,
    id: u32,
) -> AgentdResult<()> {
    let (word, mask) = bulk_output_retired_bit(id).ok_or_else(|| {
        AgentdError::ExecSession(format!("cannot retire unassigned bulk correlation {id}"))
    })?;
    let bitmap = retired.entry(incarnation).or_default();
    if bitmap.len() <= word {
        bitmap.resize(word + 1, 0);
    }
    bitmap[word] |= mask;
    Ok(())
}

/// Accept current ownership, silently reject stale ownership, and fail cross-client spoofing.
fn validate_bulk_client_incarnation(
    state: &AgentState,
    id: u32,
    claimed: ClientIncarnation,
) -> AgentdResult<bool> {
    if client_incarnation_for_id(state, id) == Some(claimed) {
        return Ok(true);
    }
    if state
        .client_incarnations
        .values()
        .any(|current| *current == claimed)
    {
        return Err(AgentdError::ExecSession(format!(
            "dedicated bulk record correlation {id} lies outside its client incarnation range"
        )));
    }
    Ok(false)
}

async fn acquire_bulk_input_permit(
    admission: Option<(Arc<Semaphore>, usize)>,
) -> AgentdResult<OwnedSemaphorePermit> {
    let (budget, payload_len) = admission.expect("bulk admission future is guarded by queue state");
    let charged = u32::try_from(payload_len)
        .map_err(|_| AgentdError::ExecSession("bulk input payload budget overflow".into()))?;
    budget
        .acquire_many_owned(charged)
        .await
        .map_err(|error| AgentdError::ExecSession(format!("bulk input budget closed: {error}")))
}

/// Validate that an internal lifecycle message names one complete relay-owned range.
fn validate_relay_client_range(id_start: u32, id_end_exclusive: u32) -> AgentdResult<u32> {
    canonical_relay_client_range(id_start, id_end_exclusive).ok_or_else(|| {
        AgentdError::ExecSession(format!(
            "invalid relay client range [{id_start}, {id_end_exclusive})"
        ))
    })
}

fn establish_relay_client(
    state: &mut AgentState,
    connected: RelayClientConnected,
) -> AgentdResult<()> {
    let slot = validate_relay_client_range(connected.id_start, connected.id_end_exclusive)?;
    if connected.incarnation == [0; CLIENT_INCARNATION_SIZE] {
        return Err(AgentdError::ExecSession(
            "relay client incarnation cannot be zero".into(),
        ));
    }
    if state
        .client_incarnations
        .get(&slot)
        .is_some_and(|current| *current != connected.incarnation)
    {
        return Err(AgentdError::ExecSession(format!(
            "relay client slot {slot} was replaced before acknowledged disconnect"
        )));
    }
    state
        .client_incarnations
        .insert(slot, connected.incarnation);
    Ok(())
}

/// Remove one current range owner; return false for a stale disconnect that was ignored.
fn disconnect_relay_client(
    state: &mut AgentState,
    disconnected: RelayClientDisconnected,
    session_tx: &SessionOutputSender,
) -> AgentdResult<(bool, Option<tokio::sync::oneshot::Receiver<()>>)> {
    let slot = validate_relay_client_range(disconnected.id_start, disconnected.id_end_exclusive)?;
    if let Some(incarnation) = disconnected.incarnation {
        if state.client_incarnations.get(&slot) != Some(&incarnation) {
            return Ok((false, None));
        }
        state.client_incarnations.remove(&slot);
    } else if state.client_incarnations.contains_key(&slot) {
        return Err(AgentdError::ExecSession(
            "bound dual-port range cleanup omitted its incarnation".into(),
        ));
    }
    cleanup_relay_client_range(state, disconnected.id_start, disconnected.id_end_exclusive);
    let scheduler_cleanup = match disconnected.incarnation {
        Some(incarnation) => session_tx
            .drop_bulk_incarnation(incarnation)
            .map_err(|error| AgentdError::ExecSession(error.into()))?,
        None => None,
    };
    Ok((true, scheduler_cleanup))
}

/// Tear down resources and reorder state belonging to one relay-owned correlation range.
fn cleanup_relay_client_range(state: &mut AgentState, id_start: u32, id_end_exclusive: u32) {
    state.sessions.retain(|id, session| {
        let keep = *id < id_start || *id >= id_end_exclusive;
        if !keep {
            // The SDK owner disappeared, so no later stdin/signal request can terminate this tree.
            // Kill the process group now and drop its PTY/stdin handles with the session entry.
            let _ = session.send_signal(9);
        }
        keep
    });
    state.fs.close_owner_range(id_start, id_end_exclusive);
    abort_read_sessions_in_owner_range(&mut state.read_sessions, id_start, id_end_exclusive);
    state.write_sessions.retain(|_, session| {
        let owner_id = session.owner_id();
        owner_id < id_start || owner_id >= id_end_exclusive
    });
    state.bulk_write_workers.retain(|id, worker| {
        let keep = *id < id_start || *id >= id_end_exclusive;
        if !keep {
            worker.task.abort();
        }
        keep
    });
    close_tcp_sessions_in_owner_range(&mut state.tcp_sessions, id_start, id_end_exclusive);
    clear_bulk_receive_range(state, id_start, id_end_exclusive);
}

/// Detach transport ownership while retaining the complete guest process lifetime.
async fn restore_client_state(
    state: &mut AgentState,
    sender: &mut SessionOutputSender,
) -> AgentdResult<()> {
    let generation = sender.generation();
    state
        .detached_sessions
        .extend(
            std::mem::take(&mut state.sessions)
                .into_iter()
                .map(|(id, mut session)| {
                    session.detach_stdin();
                    ((generation, id), session)
                }),
        );
    state.client_incarnations.clear();
    for (_, session) in state.read_sessions.drain() {
        session.abort();
    }
    for (_, worker) in state.bulk_write_workers.drain() {
        worker.task.abort();
        let _ = worker.task.await;
    }
    state.write_sessions.clear();
    for (_, session) in state.tcp_sessions.drain() {
        session.close();
    }
    state.fs.clear();
    state.bulk_received_offsets.clear();
    state.pending_bulk_finishes.clear();
    // The host drains both physical ports during this barrier. A partially written old record
    // must finish, not be interrupted midway and desynchronize the bulk byte stream.
    time::timeout(Duration::from_secs(5), sender.restore_generation())
        .await
        .map_err(|_| {
            AgentdError::ExecSession(
                "restore bulk cleanup timed out; workloads remain frozen".into(),
            )
        })?
        .map_err(|error| AgentdError::ExecSession(error.into()))
}

/// Retired producers still drain stdout/stderr so inherited children never hit a closed pipe.
fn discard_inherited_output(
    state: &mut AgentState,
    envelope: &SessionOutputEnvelope,
    generation: u64,
) -> bool {
    if envelope.generation == generation {
        return false;
    }
    if matches!(envelope.output, SessionOutput::Exited(_)) {
        state
            .detached_sessions
            .remove(&(envelope.generation, envelope.id));
    }
    true
}

// Keep the loop-owned latch and output generation explicit at this dispatch boundary; merging
// them into AgentState would obscure the ownership needed by restore and background producers.
#[allow(clippy::too_many_arguments)]
async fn handle_message_with_charge(
    msg: Message,
    state: &mut AgentState,
    activity: &mut ActivityTracker,
    root_session_tx: &mut SessionOutputSender,
    out_buf: &mut Vec<u8>,
    config: &AgentdConfig,
    workload: &mut WorkloadLatch,
    heartbeat_control: &heartbeat::HeartbeatControl,
    mut input_charge: Option<InputCharge>,
) -> AgentdResult<()> {
    // Background producers retain the range owner that opened them. The main loop can then drop
    // queued output after a disconnect instead of relabelling it with a recycled correlation ID.
    let session_tx = root_session_tx.with_incarnation(client_incarnation_for_id(state, msg.id));
    match msg.t {
        MessageType::RootDiskPrepare | MessageType::RootDiskGrow => {
            let Some(request) = decode_payload_or_core_error::<
                microsandbox_protocol::core::RootDiskGrow,
            >(&msg, out_buf)?
            else {
                return Ok(());
            };
            let apply = msg.t == MessageType::RootDiskGrow;
            let result = tokio::task::spawn_blocking(move || {
                crate::root_disk::resize(request.size_bytes, apply)
            })
            .await
            .map_err(|e| AgentdError::ExecSession(format!("root grow worker: {e}")))?;
            let reply = match result {
                Ok(state) => Message::with_payload(MessageType::RootDiskState, msg.id, &state),
                Err(message) => Message::with_payload(
                    MessageType::CoreError,
                    msg.id,
                    &CoreError {
                        kind: CoreErrorKind::CapabilityUnavailable,
                        message,
                        offending_type: Some(msg.t.as_str().into()),
                        workload_failure: None,
                    },
                ),
            }
            .map_err(|e| AgentdError::ExecSession(format!("encode root capacity: {e}")))?;
            codec::encode_to_buf(&reply, out_buf).map_err(|e| {
                AgentdError::ExecSession(format!("encode root capacity frame: {e}"))
            })?;
        }

        MessageType::Ping => {
            let Some(_) = decode_payload_or_core_error::<Ping>(&msg, out_buf)? else {
                return Ok(());
            };
            let reply = Message::with_payload(MessageType::Pong, msg.id, &Pong {})
                .map_err(|e| AgentdError::ExecSession(format!("encode pong: {e}")))?;
            codec::encode_to_buf(&reply, out_buf)
                .map_err(|e| AgentdError::ExecSession(format!("encode pong frame: {e}")))?;
        }

        MessageType::Touch => {
            let Some(_) = decode_payload_or_core_error::<Touch>(&msg, out_buf)? else {
                return Ok(());
            };
            activity.record_host_message();
            let reply = Message::with_payload(
                MessageType::Touched,
                msg.id,
                &Touched {
                    activity_seq: activity.activity_seq,
                },
            )
            .map_err(|e| AgentdError::ExecSession(format!("encode touched: {e}")))?;
            codec::encode_to_buf(&reply, out_buf)
                .map_err(|e| AgentdError::ExecSession(format!("encode touched frame: {e}")))?;
        }

        MessageType::WorkloadFreeze => {
            let Some(request) = decode_payload_or_core_error::<WorkloadFreeze>(&msg, out_buf)?
            else {
                return Ok(());
            };
            let position = state.input_window.position();
            if state.pending_freeze.as_ref().is_some_and(|pending| {
                pending
                    .payload::<WorkloadFreeze>()
                    .is_ok_and(|old| old != request)
            }) {
                encode_workload_error(
                    &msg,
                    &request.attempt_id,
                    WorkloadLatchError::Conflict("another transport cut is pending".into()),
                    out_buf,
                )?;
                return Ok(());
            }
            if workload.is_frozen() {
                if let Err(error) = workload.require_frozen_attempt(&request.attempt_id) {
                    encode_workload_error(&msg, &request.attempt_id, error, out_buf)?;
                    return Ok(());
                }
                if state
                    .frozen_host_input
                    .is_some_and(|cut| cut != request.host_input)
                {
                    encode_workload_error(
                        &msg,
                        &request.attempt_id,
                        WorkloadLatchError::Conflict("frozen transport cut cannot change".into()),
                        out_buf,
                    )?;
                    return Ok(());
                }
            }
            if request.host_input.control_bytes != position.control_bytes
                || request.host_input.control_frames != position.control_frames
                || request.host_input.bulk_bytes < position.bulk_bytes
                || request.host_input.bulk_frames < position.bulk_frames
            {
                encode_workload_error(
                    &msg,
                    &request.attempt_id,
                    WorkloadLatchError::Conflict(
                        "transport input cut differs from received complete frames".into(),
                    ),
                    out_buf,
                )?;
                return Ok(());
            }
            state.aborted_transport_attempt = None;
            if request.host_input != position {
                // Retain the private request while the independently ordered bulk prefix
                // arrives. Decoding owns its bytes; application consumption is not required.
                state.pending_freeze = Some(msg);
                return Ok(());
            }
            state.pending_freeze = None;
            let was_frozen = workload.is_frozen();
            match workload.freeze(&request.attempt_id) {
                Ok(()) => {
                    if !was_frozen {
                        // A new capture can reuse a human-selected checkpoint name.
                        state.restored_attempt = None;
                    }
                    if let Err(pause_error) = heartbeat_control.pause() {
                        let rollback = workload.thaw(&request.attempt_id).err();
                        let message = match rollback {
                            Some(error) => format!(
                                "heartbeat checkpoint gate failed: {pause_error}; workload rollback failed: {error}"
                            ),
                            None => format!("heartbeat checkpoint gate failed: {pause_error}"),
                        };
                        encode_workload_error(
                            &msg,
                            &request.attempt_id,
                            WorkloadLatchError::Io(std::io::Error::other(message)),
                            out_buf,
                        )?;
                    } else {
                        state.output_parked = true;
                        state.frozen_host_input = Some(position);
                        state.frozen_guest_bulk_bytes = root_session_tx
                            .park_bulk_output()
                            .await
                            .map_err(|error| AgentdError::ExecSession(error.into()))?;
                        // Agent upload workers are outside the workload cgroup. A capture
                        // cannot certify clean external pages while one may still write.
                        // Resident pause remains available; only mount capture needs this proof.
                        let external_mount_tags = request.external_mount_tags.clone();
                        let external_mounts_synced = if external_mount_tags.is_empty() {
                            true
                        } else if state.bulk_write_workers.is_empty() {
                            let permit = crate::mount_checkpoint::try_start_sync();
                            if let Some(permit) = permit {
                                matches!(
                                    time::timeout(
                                        std::time::Duration::from_secs(20),
                                        tokio::task::spawn_blocking(move || {
                                            // A timed-out join does not cancel syncfs. Keep the
                                            // reservation in the worker until the actual flush ends.
                                            let _permit = permit;
                                            crate::mount_checkpoint::sync_external_mounts(
                                                external_mount_tags,
                                            )
                                        }),
                                    )
                                    .await,
                                    Ok(Ok(Ok(())))
                                )
                            } else {
                                false
                            }
                        } else {
                            false
                        };
                        let reply = Message::with_payload(
                            MessageType::WorkloadFrozen,
                            msg.id,
                            &WorkloadFrozen {
                                attempt_id: request.attempt_id,
                                guest_bulk_bytes_target: state.frozen_guest_bulk_bytes,
                                input_credit: state.input_window.credit()?,
                                external_mounts_synced,
                            },
                        )
                        .map_err(|error| {
                            AgentdError::ExecSession(format!(
                                "encode workload-frozen response: {error}"
                            ))
                        })?;
                        codec::encode_to_buf(&reply, out_buf).map_err(|error| {
                            AgentdError::ExecSession(format!(
                                "encode workload-frozen frame: {error}"
                            ))
                        })?;
                    }
                }
                Err(error) => encode_workload_error(&msg, &request.attempt_id, error, out_buf)?,
            }
        }

        MessageType::WorkloadThaw => {
            let Some(request) = decode_payload_or_core_error::<WorkloadThaw>(&msg, out_buf)? else {
                return Ok(());
            };
            if state.pending_freeze.as_ref().is_some_and(|pending| {
                pending
                    .payload::<WorkloadFreeze>()
                    .is_ok_and(|freeze| freeze.attempt_id != request.attempt_id)
            }) {
                encode_workload_error(
                    &msg,
                    &request.attempt_id,
                    WorkloadLatchError::Conflict("another transport cut is pending".into()),
                    out_buf,
                )?;
                return Ok(());
            }
            if state.pending_freeze.as_ref().is_some_and(|pending| {
                pending
                    .payload::<WorkloadFreeze>()
                    .is_ok_and(|freeze| freeze.attempt_id == request.attempt_id)
            }) && !workload.is_frozen()
                || (!workload.is_frozen()
                    && state.aborted_transport_attempt.as_deref() == Some(&request.attempt_id))
            {
                if request.mode != microsandbox_protocol::core::WorkloadThawMode::Continue {
                    encode_workload_error(
                        &msg,
                        &request.attempt_id,
                        WorkloadLatchError::Conflict(
                            "restore requires a completed transport cut".into(),
                        ),
                        out_buf,
                    )?;
                    return Ok(());
                }
                if let Some(pending) = state.pending_freeze.take() {
                    // The abandoned Freeze RPC still owns a private host reply slot. Complete
                    // it explicitly before acknowledging the independent recovery Thaw RPC.
                    encode_workload_error(
                        &pending,
                        &request.attempt_id,
                        WorkloadLatchError::Conflict(
                            "transport cut aborted by source continuation".into(),
                        ),
                        out_buf,
                    )?;
                }
                state.aborted_transport_attempt = Some(request.attempt_id.clone());
                encode_input_credit(state.input_window.credit()?, out_buf)?;
                let reply = Message::with_payload(
                    MessageType::WorkloadThawed,
                    msg.id,
                    &WorkloadThawed {
                        attempt_id: request.attempt_id,
                    },
                )?;
                codec::encode_to_buf(&reply, out_buf)?;
                return Ok(());
            }
            if request.mode == microsandbox_protocol::core::WorkloadThawMode::Restore
                && state.restored_attempt.as_deref() != Some(&request.attempt_id)
            {
                if let Err(error) = workload.require_frozen_attempt(&request.attempt_id) {
                    encode_workload_error(&msg, &request.attempt_id, error, out_buf)?;
                    return Ok(());
                }
                // Never call ordinary disconnect here: it kills the very processes we captured.
                restore_client_state(state, root_session_tx).await?;
                state.restored_attempt = Some(request.attempt_id.clone());
            }
            match workload.thaw(&request.attempt_id) {
                Ok(()) => {
                    heartbeat_control.resume();
                    // Cumulative grants include refunds from detached transfer cleanup; accepted
                    // stdin remains charged until its inherited process consumes it after thaw.
                    encode_input_credit(state.input_window.credit()?, out_buf)?;
                    state.resume_output_after_flush = true;
                    state.frozen_host_input = None;
                    let reply = Message::with_payload(
                        MessageType::WorkloadThawed,
                        msg.id,
                        &WorkloadThawed {
                            attempt_id: request.attempt_id,
                        },
                    )
                    .map_err(|error| {
                        AgentdError::ExecSession(format!(
                            "encode workload-thawed response: {error}"
                        ))
                    })?;
                    codec::encode_to_buf(&reply, out_buf).map_err(|error| {
                        AgentdError::ExecSession(format!("encode workload-thawed frame: {error}"))
                    })?;
                }
                Err(error) => encode_workload_error(&msg, &request.attempt_id, error, out_buf)?,
            }
        }

        MessageType::ExecRequest => {
            let Some(mut req) = decode_payload_or_core_error::<ExecRequest>(&msg, out_buf)? else {
                return Ok(());
            };
            if req.cwd.is_none() {
                req.cwd = config.default_cwd().map(str::to_string);
            }
            prepend_scripts_to_path(&mut req);
            if workload.is_frozen() {
                encode_exec_failed(
                    msg.id,
                    ExecFailed {
                        kind: ExecFailureKind::Other,
                        errno: None,
                        errno_name: None,
                        message: "sandbox workload is frozen for checkpoint activation".into(),
                        stage: Some("workload_latch".into()),
                    },
                    out_buf,
                )?;
                return Ok(());
            }
            let workload_placement = match workload.placement() {
                Ok(placement) => placement,
                Err(error) => {
                    encode_exec_failed(
                        msg.id,
                        ExecFailed {
                            kind: ExecFailureKind::Other,
                            errno: None,
                            errno_name: None,
                            message: error.to_string(),
                            stage: Some("workload_cgroup".into()),
                        },
                        out_buf,
                    )?;
                    return Ok(());
                }
            };
            match ExecSession::spawn(
                msg.id,
                &req,
                session_tx.clone(),
                config.user.as_deref(),
                config.security_profile,
                workload_placement,
            ) {
                Ok(session) => {
                    let reply = Message::with_payload(
                        MessageType::ExecStarted,
                        msg.id,
                        &ExecStarted { pid: session.pid() },
                    )
                    .map_err(|e| AgentdError::ExecSession(format!("encode started: {e}")))?;
                    codec::encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode started frame: {e}"))
                    })?;
                    state.sessions.insert(msg.id, session);
                }
                Err(e) => {
                    // Send a typed `ExecFailed` so the host can render a
                    // useful message + hint. `ExecSpawnFailed` already
                    // carries the structured payload; other error
                    // variants (free-form `ExecSession(_)` etc.) get
                    // wrapped as `Other` with the message preserved.
                    let payload = match &e {
                        AgentdError::ExecSpawnFailed(p) => p.clone(),
                        other => ExecFailed {
                            kind: ExecFailureKind::Other,
                            errno: None,
                            errno_name: None,
                            message: other.to_string(),
                            stage: None,
                        },
                    };
                    let reply = Message::with_payload(MessageType::ExecFailed, msg.id, &payload)
                        .map_err(|e| AgentdError::ExecSession(format!("encode failed: {e}")))?;
                    codec::encode_to_buf(&reply, out_buf).map_err(|e| {
                        AgentdError::ExecSession(format!("encode failed frame: {e}"))
                    })?;
                    eprintln!("failed to spawn exec session {}: {e}", msg.id);
                }
            }
        }

        MessageType::ExecStdin => {
            let Some(stdin) = decode_payload_or_core_error::<ExecStdin>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.sessions.get_mut(&msg.id)
                && let Err(error) = session.enqueue_stdin(stdin.data, input_charge.take())
            {
                encode_stdin_error(msg.id, &AgentdError::Io(error), out_buf)?;
            }
        }

        MessageType::ExecResize => {
            let Some(resize) = decode_payload_or_core_error::<ExecResize>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.sessions.get(&msg.id) {
                let _ = session.resize(resize.rows, resize.cols);
            }
        }

        MessageType::ExecSignal => {
            let Some(signal) = decode_payload_or_core_error::<ExecSignal>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.sessions.get(&msg.id) {
                let _ = session.send_signal(signal.signal);
            }
        }

        MessageType::FsRequest => {
            let Some(req) = decode_payload_or_core_error::<FsRequest>(&msg, out_buf)? else {
                return Ok(());
            };
            match fs::handle_fs_request(msg.id, msg.v, req, &mut state.fs, out_buf, &session_tx)
                .await
            {
                Ok(Some(FsStreamSession::Read(rs))) => {
                    state.read_sessions.insert(msg.id, rs);
                }
                Ok(Some(FsStreamSession::Write(ws))) => {
                    state.write_sessions.insert(msg.id, ws);
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("fs request error for {}: {e}", msg.id);
                }
            }
        }

        MessageType::FsData => {
            let Some(data) = decode_payload_or_core_error::<FsData>(&msg, out_buf)? else {
                return Ok(());
            };
            let len = data.data.len();
            if let Some(session) = state.write_sessions.get_mut(&msg.id) {
                match fs::handle_fs_data(msg.id, data, session, out_buf).await {
                    Ok(true) => {
                        // Session complete — remove it.
                        state.write_sessions.remove(&msg.id);
                        clear_bulk_receive_state(state, msg.id);
                    }
                    Ok(false) => {
                        activity.add_fs_bytes(len);
                    }
                    Err(e) => {
                        eprintln!("fs data error for {}: {e}", msg.id);
                        state.write_sessions.remove(&msg.id);
                        clear_bulk_receive_state(state, msg.id);
                    }
                }
            } else {
                // No write session for this ID — send error response.
                let resp = microsandbox_protocol::fs::FsResponse {
                    ok: false,
                    error: Some(format!("unknown write session: {}", msg.id)),
                    data: None,
                };
                let reply = Message::with_payload(MessageType::FsResponse, msg.id, &resp)
                    .map_err(|e| AgentdError::ExecSession(format!("encode fs error: {e}")))?;
                codec::encode_to_buf(&reply, out_buf)
                    .map_err(|e| AgentdError::ExecSession(format!("encode fs error frame: {e}")))?;
            }
        }

        MessageType::BulkCredit => {
            let Some(credit) = decode_payload_or_core_error::<BulkCredit>(&msg, out_buf)? else {
                return Ok(());
            };
            match credit.kind {
                BulkKind::Filesystem => {
                    let result = state
                        .read_sessions
                        .get(&msg.id)
                        .ok_or_else(|| format!("unknown filesystem read session: {}", msg.id))
                        .and_then(|session| session.apply_credit(credit));
                    if let Err(error) = result {
                        encode_bulk_fs_failure(msg.id, error, out_buf)?;
                        cancel_bulk_correlation(msg.id, BulkKind::Filesystem, state, &session_tx);
                    }
                }
                BulkKind::Tcp => {
                    let result = match state.tcp_sessions.get(&msg.id) {
                        Some(session) => session.apply_credit(credit).await,
                        // A terminal may retire the producer before the other physical lane
                        // finishes delivering its output. Late credit has no recipient and must
                        // not cancel that tail or manufacture a second terminal response.
                        None => Ok(()),
                    };
                    if let Err(error) = result {
                        encode_bulk_tcp_failure(msg.id, error, out_buf)?;
                        cancel_bulk_correlation(msg.id, BulkKind::Tcp, state, &session_tx);
                    }
                }
            }
        }

        MessageType::BulkFinish => {
            let Some(finish) = decode_payload_or_core_error::<BulkFinish>(&msg, out_buf)? else {
                return Ok(());
            };
            let received_offset = state
                .bulk_received_offsets
                .get(&msg.id)
                .copied()
                .unwrap_or(0);
            if has_bulk_receive_session(state, msg.id, finish.kind)
                && finish.final_offset > received_offset
            {
                if state.pending_bulk_finishes.insert(msg.id, finish).is_some() {
                    encode_bulk_cancel(
                        msg.id,
                        finish.kind,
                        BulkCancelReason::ProtocolState,
                        "duplicate deferred bulk finish".into(),
                        out_buf,
                    )?;
                    cancel_bulk_correlation(msg.id, finish.kind, state, &session_tx);
                }
            } else {
                dispatch_bulk_finish(msg.id, finish, state, out_buf, &session_tx).await?;
            }
        }

        MessageType::BulkCancel => {
            let Some(cancel) = decode_payload_or_core_error::<BulkCancel>(&msg, out_buf)? else {
                return Ok(());
            };
            cancel_bulk_correlation(msg.id, cancel.kind, state, &session_tx);
            // Cancellation owns the correlation through its ordinary terminal response. This
            // gives SDK dispatch a precise point at which it may retire the route while late raw
            // records admitted under pre-cancel credit are still being discarded.
            encode_bulk_terminal_failure(msg.id, cancel.kind, cancel.message, out_buf)?;
        }

        MessageType::BulkAccepted => {
            encode_core_error_if_supported(
                &msg,
                msg.id,
                CoreErrorKind::UnsupportedMessageType,
                "host cannot accept a guest-initiated bulk offer".into(),
                Some(msg.t.as_str().to_string()),
                out_buf,
            )?;
        }

        MessageType::TcpConnect => {
            let Some(req) = decode_payload_or_core_error::<TcpConnect>(&msg, out_buf)? else {
                return Ok(());
            };
            if req.bulk.is_some() && msg.v < BULK_PROTOCOL_VERSION {
                encode_tcp_failed(
                    msg.id,
                    format!("raw bulk offer requires protocol generation {BULK_PROTOCOL_VERSION}"),
                    out_buf,
                )?;
                return Ok(());
            }
            // The connect runs inside the session task; the agent loop never
            // blocks on it. Success or failure arrives later as a tcp frame.
            let session = TcpSession::open(msg.id, req, &session_tx);
            state.tcp_sessions.insert(msg.id, session);
        }

        MessageType::TcpData => {
            let Some(data) = decode_payload_or_core_error::<TcpData>(&msg, out_buf)? else {
                return Ok(());
            };
            let len = data.data.len();
            if let Some(session) = state.tcp_sessions.get(&msg.id) {
                if let Err(e) = session
                    .write_data_charged(data.data, input_charge.take())
                    .await
                {
                    state.tcp_sessions.remove(&msg.id);
                    clear_bulk_receive_state(state, msg.id);
                    encode_tcp_failed(msg.id, e, out_buf)?;
                } else {
                    activity.add_tcp_bytes(len);
                }
            } else {
                encode_tcp_failed(msg.id, format!("unknown TCP session: {}", msg.id), out_buf)?;
            }
        }

        MessageType::TcpEof => {
            let Some(_) = decode_payload_or_core_error::<TcpEof>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.tcp_sessions.get(&msg.id)
                && let Err(e) = session.close_write_charged(input_charge.take()).await
            {
                state.tcp_sessions.remove(&msg.id);
                clear_bulk_receive_state(state, msg.id);
                encode_tcp_failed(msg.id, e, out_buf)?;
            }
        }

        MessageType::TcpClose => {
            let Some(_) = decode_payload_or_core_error::<TcpClose>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Some(session) = state.tcp_sessions.remove(&msg.id) {
                session.close();
            }
            clear_bulk_receive_state(state, msg.id);
        }

        MessageType::RelayClientDisconnected => {
            let Some(disconnected) =
                decode_payload_or_core_error::<RelayClientDisconnected>(&msg, out_buf)?
            else {
                return Ok(());
            };
            // A late cleanup for an old owner must never affect a recycled range.
            let disconnect_ack =
                disconnected
                    .incarnation
                    .map(|incarnation| RelayClientDisconnectedAck {
                        id_start: disconnected.id_start,
                        id_end_exclusive: disconnected.id_end_exclusive,
                        incarnation,
                    });
            let (removed, scheduler_cleanup) =
                disconnect_relay_client(state, disconnected, &session_tx)?;
            if removed && let Some(disconnect_ack) = disconnect_ack {
                if let Some(cleanup) = scheduler_cleanup {
                    // Keep the single-vCPU control actor available while the bulk actor reaches
                    // its cleanup cut. The acknowledgement is emitted through the ordinary
                    // control queue only after matching queued records release their permits.
                    let output_tx = session_tx.clone();
                    tokio::spawn(async move {
                        if cleanup.await.is_ok() {
                            let frame =
                                encode_relay_client_disconnected_ack(disconnect_ack).to_vec();
                            let _ = output_tx
                                .send(
                                    0,
                                    SessionOutput::Raw(RawSessionOutput::new(
                                        frame,
                                        RawActivity::default(),
                                        None,
                                    )),
                                )
                                .await;
                        }
                    });
                } else {
                    // Combined leased mode has no dedicated scheduler, so resource cleanup itself
                    // is the acknowledgement cut.
                    out_buf
                        .extend_from_slice(&encode_relay_client_disconnected_ack(disconnect_ack));
                }
            }
        }

        MessageType::ClockSync => {
            let Some(sync) = decode_payload_or_core_error::<ClockSync>(&msg, out_buf)? else {
                return Ok(());
            };
            if let Err(e) = clock::sync_realtime_unix_nanos(sync.unix_time_nanos) {
                eprintln!("clock: failed to sync realtime clock: {e}");
            }
        }

        MessageType::Shutdown => {
            // Graceful shutdown — signal all sessions, then ask the guest
            // kernel to power off so block-root filesystems can shut down
            // cleanly instead of leaving ext4 journal recovery pending.
            for session in state
                .sessions
                .drain()
                .map(|(_, session)| session)
                .chain(state.detached_sessions.drain().map(|(_, session)| session))
            {
                let _ = session.send_signal(15); // SIGTERM
            }
            state.write_sessions.clear();
            for (_, worker) in state.bulk_write_workers.drain() {
                worker.task.abort();
            }
            for (_, session) in state.tcp_sessions.drain() {
                session.close();
            }
            state.fs.clear();

            // A request is not completion. In handoff mode the foreign init owns the
            // shutdown schedule; keep serving until the kernel actually powers off.
            // Exiting agentd here can itself tear down the VM and bypass that schedule.
            if let Err(error) = request_guest_poweroff() {
                eprintln!("agentd: graceful poweroff request failed: {error}");
            }
        }

        _ => {
            // Ignore unknown or unexpected message types.
        }
    }

    Ok(())
}

/// Prepends `/.msb/scripts` to PATH in the exec request's environment.
///
/// If the request already has a PATH entry, prepends to it. Otherwise
/// inherits from agentd's environment and prepends.
/// Returns whether a host message should refresh the sandbox idle timer.
///
/// Maintenance traffic such as clock synchronization and reachability checks
/// must not count as user activity, otherwise periodic host tasks would keep an
/// idle sandbox alive. `core.touch` is excluded here too because it refreshes
/// idleness explicitly in its handler, after its payload has been validated.
fn message_refreshes_idle_timer(t: &MessageType) -> bool {
    !matches!(
        t,
        MessageType::ClockSync
            | MessageType::Ping
            | MessageType::Touch
            | MessageType::WorkloadFreeze
            | MessageType::WorkloadThaw
    )
}

/// Returns whether an agent reply should refresh the sandbox idle timer.
///
/// Most guest output still represents useful sandbox activity. Maintenance
/// replies to `core.ping` and `core.touch` are excluded so `ping` is a pure
/// health check and `touch` advances activity exactly once. `core.error` is
/// also excluded because valid work already records activity on the incoming
/// request, while malformed maintenance traffic should not become a keepalive.
fn guest_message_refreshes_idle_timer(t: &MessageType) -> bool {
    !matches!(
        t,
        MessageType::Pong
            | MessageType::Touched
            | MessageType::WorkloadFrozen
            | MessageType::WorkloadThawed
            | MessageType::WorkloadTransportCredit
            | MessageType::CoreError
    )
}

/// Spawns the heartbeat pulse on a dedicated OS thread.
///
/// This thread is intentionally outside the Tokio runtime: it reads the latest
/// [`HeartbeatSnapshot`] (a lock-free `watch` borrow) and writes the heartbeat
/// file with blocking `std::fs` once per [`HEARTBEAT_INTERVAL_SECS`]. Because it
/// is an ordinary kernel-scheduled thread, a CPU-bound or I/O-saturated async
/// runtime cannot delay the pulse — which is exactly the starvation that made
/// the host kill busy-but-healthy sandboxes. The sleep is chunked so the thread
/// observes the shutdown flag promptly when the agent loop exits.
fn spawn_heartbeat_thread(
    snapshot_rx: watch::Receiver<HeartbeatSnapshot>,
    shutdown: Arc<AtomicBool>,
    control: Arc<heartbeat::HeartbeatControl>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("agentd-heartbeat".to_string())
        .spawn(move || {
            let mut heartbeat_seq = 0u64;
            let mut last_activity_seq = snapshot_rx.borrow().activity_seq;
            let mut last_activity = Utc::now();

            let interval = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
            let step = Duration::from_millis(100);

            while !shutdown.load(Ordering::Relaxed) {
                let mut slept = Duration::ZERO;
                while slept < interval {
                    if shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(step);
                    slept += step;
                }

                if !heartbeat::heartbeat_dir_exists() {
                    continue;
                }

                heartbeat_seq = heartbeat_seq.saturating_add(1);
                let snapshot = snapshot_rx.borrow().clone();
                let timestamp = Utc::now();
                if snapshot.activity_seq != last_activity_seq {
                    last_activity_seq = snapshot.activity_seq;
                    last_activity = timestamp;
                }
                let heartbeat = Heartbeat {
                    heartbeat_seq,
                    activity_seq: snapshot.activity_seq,
                    timestamp,
                    last_activity,
                    active_exec_sessions: snapshot.active_exec_sessions,
                    active_fs_streams: snapshot.active_fs_streams,
                    active_tcp_streams: snapshot.active_tcp_streams,
                    activity_counters: snapshot.counters,
                };
                let Some(_write_guard) = control.begin_write() else {
                    continue;
                };
                let _ = heartbeat::write_heartbeat(&heartbeat);
            }
        })
        .expect("failed to spawn agentd heartbeat thread")
}

fn heartbeat_snapshot(state: &AgentState, activity: &ActivityTracker) -> HeartbeatSnapshot {
    HeartbeatSnapshot {
        activity_seq: activity.activity_seq,
        active_exec_sessions: (state.sessions.len() + state.detached_sessions.len()) as u32,
        active_fs_streams: state
            .read_sessions
            .len()
            .saturating_add(state.write_sessions.len())
            .saturating_add(state.bulk_write_workers.len()) as u32,
        active_tcp_streams: state.tcp_sessions.len() as u32,
        counters: activity.counters,
    }
}

fn initial_input_credit() -> WorkloadTransportCredit {
    WorkloadTransportCredit {
        control_bytes: WORKLOAD_TRANSPORT_CONTROL_BYTES,
        control_frames: WORKLOAD_TRANSPORT_CONTROL_FRAMES,
        bulk_bytes: WORKLOAD_TRANSPORT_BULK_BYTES,
        bulk_frames: WORKLOAD_TRANSPORT_BULK_FRAMES,
    }
}

fn bulk_wire_bytes(record: &BulkRecord, dedicated: bool) -> usize {
    // The counter follows complete wire records, not destination payload consumption. Combined
    // raw frames use the same bulk allowance without the dedicated lane's incarnation prefix.
    4 + FRAME_HEADER_SIZE
        + BULK_HEADER_SIZE
        + record.payload.len()
        + if dedicated {
            CLIENT_INCARNATION_SIZE
        } else {
            0
        }
}

fn private_lifecycle_message(message: &Message) -> bool {
    message.id == u32::MAX
        && matches!(
            message.t,
            MessageType::WorkloadFreeze | MessageType::WorkloadThaw
        )
        && message.flags == message.t.flags()
}

fn input_credit_update_due(
    previous: &WorkloadTransportCredit,
    current: &WorkloadTransportCredit,
) -> bool {
    current.control_bytes.saturating_sub(previous.control_bytes) >= 64 * 1024
        || current.bulk_bytes.saturating_sub(previous.bulk_bytes) >= 64 * 1024
        || current
            .control_frames
            .saturating_sub(previous.control_frames)
            >= 16
        || current.bulk_frames.saturating_sub(previous.bulk_frames) >= 16
}

async fn wait_input_credit_deadline(deadline: Option<time::Instant>) {
    match deadline {
        Some(deadline) => time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn encode_input_credit(credit: WorkloadTransportCredit, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    // The host intercepts the reserved runtime correlation before SDK output admission, so a
    // stalled client cannot stop refunds needed by unrelated stdin and bulk producers.
    let message = Message::with_payload(MessageType::WorkloadTransportCredit, u32::MAX, &credit)?;
    codec::encode_to_buf(&message, out_buf)?;
    Ok(())
}

fn poll_pending_stdin(
    state: &mut AgentState,
    cx: &mut Context<'_>,
) -> Poll<(u32, bool, std::io::Result<()>)> {
    // Rotate the first descriptor considered so a continuously writable active session cannot
    // starve inherited input. The cursor needs no per-payload task or additional ownership queue.
    let total = state.sessions.len() + state.detached_sessions.len();
    let start = state.stdin_poll_offset.checked_rem(total).unwrap_or(0);
    for pass in 0..2 {
        let sessions = state
            .sessions
            .iter_mut()
            .map(|(id, session)| (*id, false, session))
            .chain(
                state
                    .detached_sessions
                    .iter_mut()
                    .map(|((_, id), session)| (*id, true, session)),
            );
        for (index, (id, inherited, session)) in sessions.enumerate() {
            if (pass == 0 && index < start) || (pass == 1 && index >= start) {
                continue;
            }
            if session.has_pending_stdin()
                && let Poll::Ready(result) = session.poll_pending_stdin(cx)
            {
                state.stdin_poll_offset = index + 1;
                return Poll::Ready((id, inherited, result));
            }
        }
    }
    Poll::Pending
}

fn encode_stdin_error(id: u32, error: &AgentdError, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    let message =
        Message::with_payload(MessageType::ExecStdinError, id, &stdin_error_payload(error))?;
    codec::encode_to_buf(&message, out_buf)?;
    Ok(())
}

fn publish_heartbeat_snapshot(
    heartbeat_tx: &watch::Sender<HeartbeatSnapshot>,
    state: &AgentState,
    activity: &ActivityTracker,
) {
    let _ = heartbeat_tx.send(heartbeat_snapshot(state, activity));
}

fn record_encoded_guest_messages(out_buf: &[u8], start: usize, activity: &mut ActivityTracker) {
    let mut offset = start;
    while offset + 4 <= out_buf.len() {
        let frame_len = u32::from_be_bytes([
            out_buf[offset],
            out_buf[offset + 1],
            out_buf[offset + 2],
            out_buf[offset + 3],
        ]) as usize;
        let total = 4usize.saturating_add(frame_len);
        if offset.saturating_add(total) > out_buf.len() {
            break;
        }

        if encoded_guest_message_refreshes_idle_timer(out_buf, offset, frame_len) {
            activity.record_guest_message();
        }
        offset += total;
    }
}

fn encoded_guest_message_refreshes_idle_timer(
    out_buf: &[u8],
    offset: usize,
    frame_len: usize,
) -> bool {
    let frame_end = offset.saturating_add(4).saturating_add(frame_len);
    if frame_end <= out_buf.len() {
        let mut frame = BytesMut::from(&out_buf[offset..frame_end]);
        if try_decode_relay_client_disconnected_ack_from_bytes(&mut frame)
            .is_ok_and(|ack| ack.is_some())
        {
            return false;
        }
    }
    if frame_len < microsandbox_protocol::message::FRAME_HEADER_SIZE {
        return true;
    }

    let id_start = offset + 4;
    let flags_index = id_start + 4;
    let body_start = flags_index + 1;
    let body_end = offset + 4 + frame_len;
    if body_end > out_buf.len() || body_start > body_end {
        return true;
    }

    let id = u32::from_be_bytes([
        out_buf[id_start],
        out_buf[id_start + 1],
        out_buf[id_start + 2],
        out_buf[id_start + 3],
    ]);
    let frame = codec::RawFrame {
        id,
        flags: out_buf[flags_index],
        body: out_buf[body_start..body_end].to_vec(),
    };

    codec::raw_frame_to_message(frame)
        .map(|msg| guest_message_refreshes_idle_timer(&msg.t))
        .unwrap_or(true)
}

fn apply_raw_activity(raw: RawActivity, activity: &mut ActivityTracker) {
    if raw.guest_messages != 0 {
        activity.activity_seq = activity
            .activity_seq
            .saturating_add(raw.guest_messages as u64);
        activity.counters.guest_messages = activity
            .counters
            .guest_messages
            .saturating_add(raw.guest_messages as u64);
    }
    if raw.fs_bytes > 0 {
        activity.add_fs_bytes(raw.fs_bytes);
    }
    if raw.tcp_bytes > 0 {
        activity.add_tcp_bytes(raw.tcp_bytes);
    }
}

fn complete_raw_session(
    id: u32,
    completion: Option<RawSessionCompletion>,
    read_sessions: &mut HashMap<u32, FsReadSession>,
    tcp_sessions: &mut HashMap<u32, TcpSession>,
) {
    match completion {
        Some(RawSessionCompletion::FsRead) => {
            read_sessions.remove(&id);
        }
        Some(RawSessionCompletion::FsWrite) => {}
        Some(RawSessionCompletion::Tcp) => {
            tcp_sessions.remove(&id);
        }
        None => {}
    }
}

fn abort_read_sessions_in_owner_range(
    read_sessions: &mut HashMap<u32, FsReadSession>,
    id_start: u32,
    id_end_exclusive: u32,
) {
    let mut retained = HashMap::new();
    for (id, session) in read_sessions.drain() {
        let owner_id = session.owner_id();
        if owner_id >= id_start && owner_id < id_end_exclusive {
            session.abort();
        } else {
            retained.insert(id, session);
        }
    }
    *read_sessions = retained;
}

fn close_tcp_sessions_in_owner_range(
    tcp_sessions: &mut HashMap<u32, TcpSession>,
    id_start: u32,
    id_end_exclusive: u32,
) {
    let mut retained = HashMap::new();
    for (id, session) in tcp_sessions.drain() {
        let owner_id = session.owner_id();
        if owner_id >= id_start && owner_id < id_end_exclusive {
            session.close();
        } else {
            retained.insert(id, session);
        }
    }
    *tcp_sessions = retained;
}

fn encode_tcp_failed(id: u32, error: String, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    let reply = Message::with_payload(MessageType::TcpFailed, id, &TcpFailed { error })
        .map_err(|e| AgentdError::ExecSession(format!("encode tcp failed: {e}")))?;
    codec::encode_to_buf(&reply, out_buf)
        .map_err(|e| AgentdError::ExecSession(format!("encode tcp failed frame: {e}")))?;
    Ok(())
}

fn encode_bulk_fs_failure(id: u32, error: String, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    encode_bulk_cancel(
        id,
        BulkKind::Filesystem,
        BulkCancelReason::ProtocolState,
        error.clone(),
        out_buf,
    )?;
    let response = Message::with_payload(
        MessageType::FsResponse,
        id,
        &FsResponse {
            ok: false,
            error: Some(error),
            data: None,
        },
    )
    .map_err(|error| AgentdError::ExecSession(format!("encode fs failure: {error}")))?;
    codec::encode_to_buf(&response, out_buf)
        .map_err(|error| AgentdError::ExecSession(format!("encode fs failure frame: {error}")))
}

fn encode_bulk_tcp_failure(id: u32, error: String, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    encode_bulk_cancel(
        id,
        BulkKind::Tcp,
        BulkCancelReason::ProtocolState,
        error.clone(),
        out_buf,
    )?;
    encode_tcp_failed(id, error, out_buf)
}

/// Emit the operation family's existing terminal failure without recursively sending a cancel.
fn encode_bulk_terminal_failure(
    id: u32,
    kind: BulkKind,
    error: String,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    match kind {
        BulkKind::Filesystem => {
            let response = Message::with_payload(
                MessageType::FsResponse,
                id,
                &FsResponse {
                    ok: false,
                    error: Some(error),
                    data: None,
                },
            )
            .map_err(|error| {
                AgentdError::ExecSession(format!("encode filesystem terminal failure: {error}"))
            })?;
            codec::encode_to_buf(&response, out_buf).map_err(|error| {
                AgentdError::ExecSession(format!(
                    "encode filesystem terminal failure frame: {error}"
                ))
            })
        }
        BulkKind::Tcp => encode_tcp_failed(id, error, out_buf),
    }
}

fn encode_bulk_cancel(
    id: u32,
    kind: BulkKind,
    reason: BulkCancelReason,
    message: String,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    let cancel = Message::with_payload(
        MessageType::BulkCancel,
        id,
        &BulkCancel {
            kind,
            reason,
            message,
        },
    )
    .map_err(|error| AgentdError::ExecSession(format!("encode bulk cancel: {error}")))?;
    codec::encode_to_buf(&cancel, out_buf)
        .map_err(|error| AgentdError::ExecSession(format!("encode bulk cancel frame: {error}")))
}

fn encode_core_error_if_supported(
    source: &Message,
    id: u32,
    kind: CoreErrorKind,
    message: String,
    offending_type: Option<String>,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    if !MessageType::CoreError.is_available_at(source.v) {
        return Err(AgentdError::ExecSession(format!(
            "cannot send core.error to protocol generation {}",
            source.v
        )));
    }

    encode_core_error(id, kind, message, offending_type, out_buf)
}

fn encode_core_error(
    id: u32,
    kind: CoreErrorKind,
    message: String,
    offending_type: Option<String>,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    let reply = Message::with_payload(
        MessageType::CoreError,
        id,
        &CoreError {
            kind,
            message,
            offending_type,
            workload_failure: None,
        },
    )
    .map_err(|e| AgentdError::ExecSession(format!("encode core error: {e}")))?;
    codec::encode_to_buf(&reply, out_buf)
        .map_err(|e| AgentdError::ExecSession(format!("encode core error frame: {e}")))?;
    Ok(())
}

fn encode_workload_error(
    source: &Message,
    attempt_id: &str,
    error: WorkloadLatchError,
    out_buf: &mut Vec<u8>,
) -> AgentdResult<()> {
    let kind = match &error {
        WorkloadLatchError::Unavailable(_) | WorkloadLatchError::Io(_) => {
            CoreErrorKind::CapabilityUnavailable
        }
        WorkloadLatchError::InvalidAttempt(_) => CoreErrorKind::InvalidPayload,
        WorkloadLatchError::Conflict(_) => CoreErrorKind::InvalidSession,
    };
    // Keep the existing error category readable by older hosts. Only the additive,
    // attempt-scoped detail proves that a basic-pause fallback is safe.
    let disposition = match &error {
        WorkloadLatchError::Unavailable(_) => WorkloadFailureDisposition::Unavailable,
        _ => WorkloadFailureDisposition::RecoveryRequired,
    };
    if !MessageType::CoreError.is_available_at(source.v) {
        return Err(AgentdError::ExecSession(
            "peer cannot receive workload errors".into(),
        ));
    }
    let reply = Message::with_payload(
        MessageType::CoreError,
        source.id,
        &CoreError {
            kind,
            message: error.to_string(),
            offending_type: Some(source.t.as_str().to_string()),
            workload_failure: Some(WorkloadFailure {
                attempt_id: attempt_id.to_string(),
                disposition,
            }),
        },
    )
    .map_err(|error| AgentdError::ExecSession(format!("encode workload error: {error}")))?;
    codec::encode_to_buf(&reply, out_buf)
        .map_err(|error| AgentdError::ExecSession(format!("encode workload error frame: {error}")))
}

fn encode_exec_failed(id: u32, payload: ExecFailed, out_buf: &mut Vec<u8>) -> AgentdResult<()> {
    let reply = Message::with_payload(MessageType::ExecFailed, id, &payload)
        .map_err(|error| AgentdError::ExecSession(format!("encode exec failure: {error}")))?;
    codec::encode_to_buf(&reply, out_buf)
        .map_err(|error| AgentdError::ExecSession(format!("encode exec failure frame: {error}")))?;
    Ok(())
}

fn decode_payload_or_core_error<T>(msg: &Message, out_buf: &mut Vec<u8>) -> AgentdResult<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match msg.payload::<T>() {
        Ok(payload) => Ok(Some(payload)),
        Err(error) => {
            encode_core_error_if_supported(
                msg,
                msg.id,
                CoreErrorKind::InvalidPayload,
                format!("decode payload for {}: {error}", msg.t.as_str()),
                Some(msg.t.as_str().to_string()),
                out_buf,
            )?;
            Ok(None)
        }
    }
}

/// Build an `ExecStdinError` payload from a failed `write_stdin` result.
fn stdin_error_payload(err: &AgentdError) -> ExecStdinError {
    let io_err = match err {
        AgentdError::Io(e) => Some(e),
        _ => None,
    };
    let errno = io_err.and_then(|e| e.raw_os_error());
    ExecStdinError {
        errno,
        errno_name: errno.and_then(errno_name),
        message: err.to_string(),
    }
}

/// Map common errno values to their standard names. Returns `None` for
/// codes we don't recognize; callers fall back to the numeric `errno`.
fn errno_name(code: i32) -> Option<String> {
    let name = match code {
        libc::EPIPE => "EPIPE",
        libc::EBADF => "EBADF",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::ENOSPC => "ENOSPC",
        libc::EFBIG => "EFBIG",
        _ => return None,
    };
    Some(name.to_string())
}

fn prepend_scripts_to_path(req: &mut microsandbox_protocol::exec::ExecRequest) {
    // Check if the request already specifies PATH.
    if let Some(entry) = req.env.iter_mut().find(|e| e.starts_with("PATH=")) {
        let existing = &entry["PATH=".len()..];
        *entry = format!("PATH={}", scripts_path(Some(existing)));
    } else {
        let inherited = env::var("PATH").ok();
        req.env
            .push(format!("PATH={}", scripts_path(inherited.as_deref())));
    }
}

/// Sets a file descriptor to non-blocking mode.
fn set_nonblocking(fd: i32) -> AgentdResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn cmdline_requests_dual_port(cmdline: &str) -> bool {
    cmdline
        .split_ascii_whitespace()
        .any(|argument| argument == AGENT_TRANSPORT_DUAL_PORT_CMDLINE)
}

fn random_connection_id() -> AgentdResult<[u8; 16]> {
    let mut id = [0u8; 16];
    let mut filled = 0;
    while filled < id.len() {
        let result =
            unsafe { libc::getrandom(id[filled..].as_mut_ptr().cast(), id.len() - filled, 0) };
        if result > 0 {
            filled += result as usize;
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error.into());
    }
    Ok(id)
}

fn read_exact_from_fd(
    fd: i32,
    mut buf: &mut [u8],
    deadline: Instant,
    label: &str,
) -> AgentdResult<()> {
    while !buf.is_empty() {
        if !poll_fd_until(fd, libc::POLLIN, deadline)? {
            return Err(AgentdError::ExecSession(format!(
                "timed out waiting for {label}"
            )));
        }
        match read_from_fd(fd, buf) {
            Ok(0) => {
                return Err(AgentdError::ExecSession(format!(
                    "serial port closed while waiting for {label}"
                )));
            }
            Ok(read) => {
                let (_, remainder) = std::mem::take(&mut buf).split_at_mut(read);
                buf = remainder;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn init_ack_deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(INIT_ACK_TIMEOUT_SECS)
}

fn init_ack_timeout() -> AgentdError {
    AgentdError::ExecSession("timed out waiting for init ack".into())
}

fn wait_for_init_ack(
    fd: i32,
    boot_console: &mut BootConsoleState,
    deadline: Instant,
) -> AgentdResult<()> {
    let msg = read_boot_message(fd, boot_console, deadline, "init ack")?;
    if msg.t == MessageType::InitAck {
        let _: InitAck = msg
            .payload()
            .map_err(|e| AgentdError::ExecSession(format!("decode init ack payload: {e}")))?;
        return Ok(());
    }

    Err(AgentdError::ExecSession(format!(
        "expected core.init.ack, got {}",
        msg.t.as_str()
    )))
}

fn read_boot_message(
    fd: i32,
    state: &mut BootConsoleState,
    deadline: Instant,
    context: &str,
) -> AgentdResult<Message> {
    let mut read_buf = [0u8; 4096];
    loop {
        if let Some(msg) = codec::try_decode_from_buf(&mut state.input)
            .map_err(|e| AgentdError::ExecSession(format!("decode {context}: {e}")))?
        {
            return Ok(msg);
        }
        if state.input.len() > MAX_INPUT_BUF_SIZE {
            return Err(AgentdError::ExecSession(format!(
                "serial input buffer exceeded maximum size while waiting for {context}"
            )));
        }
        if !poll_fd_until(fd, libc::POLLIN, deadline)? {
            return Err(if context == "init ack" {
                init_ack_timeout()
            } else {
                AgentdError::ExecSession(format!("timed out waiting for {context}"))
            });
        }
        let n = match read_from_fd(fd, &mut read_buf) {
            Ok(n) => n,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if n == 0 {
            return Err(AgentdError::ExecSession(format!(
                "serial port closed while waiting for {context}"
            )));
        }
        state.input.extend_from_slice(&read_buf[..n]);
    }
}

fn poll_fd_until(fd: i32, events: i16, deadline: Instant) -> AgentdResult<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }

        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let timeout_ms = if timeout_ms == 0 { 1 } else { timeout_ms };
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 {
            return Ok(true);
        }
        if ret == 0 {
            return Ok(false);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err.into());
    }
}

/// Reads from a raw fd (non-blocking).
fn read_from_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_all_to_fd(fd: i32, mut buf: &[u8], deadline: Instant) -> AgentdResult<()> {
    while !buf.is_empty() {
        match write_to_fd(fd, buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !poll_fd_until(fd, libc::POLLOUT, deadline)? {
                    return Err(init_ack_timeout());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// Flushes the write buffer to the async fd.
async fn flush_write_buf(fd: &AsyncFd<std::fs::File>, buf: &mut Vec<u8>) -> AgentdResult<()> {
    write_all_async_fd(fd, buf).await?;
    buf.clear();
    Ok(())
}

/// Write an immutable region to the nonblocking serial descriptor with cursor advancement.
async fn write_all_async_fd(fd: &AsyncFd<std::fs::File>, buf: &[u8]) -> AgentdResult<()> {
    let mut written = 0;
    while written < buf.len() {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| write_to_fd(inner.get_ref().as_raw_fd(), &buf[written..])) {
            Ok(Ok(n)) => {
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                }
                written += n;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) => return Err(e.into()),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

/// Writes a raw bulk header and payload with cursor-safe `writev` calls.
async fn write_bulk_record_async_fd(
    fd: &AsyncFd<std::fs::File>,
    record: &BulkRecord,
) -> AgentdResult<()> {
    let header = codec::encode_bulk_header(record)
        .map_err(|error| AgentdError::ExecSession(format!("encode bulk header: {error}")))?;
    write_bulk_parts_async_fd(fd, &header, &record.payload).await
}

/// Prefix a dedicated-lane record without copying its opaque payload.
async fn write_incarnated_bulk_record_async_fd(
    fd: &AsyncFd<std::fs::File>,
    incarnation: ClientIncarnation,
    record: &BulkRecord,
) -> AgentdResult<()> {
    let public_header = codec::encode_bulk_header(record)
        .map_err(|error| AgentdError::ExecSession(format!("encode bulk header: {error}")))?;
    let mut header = [0u8; CLIENT_INCARNATION_SIZE + 4 + FRAME_HEADER_SIZE + BULK_HEADER_SIZE];
    header[..CLIENT_INCARNATION_SIZE].copy_from_slice(&incarnation);
    header[CLIENT_INCARNATION_SIZE..].copy_from_slice(&public_header);
    write_bulk_parts_async_fd(fd, &header, &record.payload).await
}

async fn write_bulk_parts_async_fd(
    fd: &AsyncFd<std::fs::File>,
    header: &[u8],
    payload: &[u8],
) -> AgentdResult<()> {
    let mut header_offset = 0;
    let mut payload_offset = 0;

    while header_offset < header.len() || payload_offset < payload.len() {
        let mut guard = fd.writable().await?;
        let result = guard.try_io(|inner| {
            write_vectored_to_fd(
                inner.get_ref().as_raw_fd(),
                &header[header_offset..],
                &payload[payload_offset..],
            )
        });
        let written = match result {
            Ok(Ok(0)) => {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            Ok(Ok(written)) => written,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error.into()),
            Err(_would_block) => continue,
        };

        let header_remaining = header.len() - header_offset;
        if written < header_remaining {
            header_offset += written;
        } else {
            header_offset = header.len();
            payload_offset += written - header_remaining;
        }
    }

    Ok(())
}

/// Writes to a raw fd (non-blocking).
fn write_to_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_vectored_to_fd(fd: i32, header: &[u8], payload: &[u8]) -> std::io::Result<usize> {
    if header.is_empty() {
        return write_to_fd(fd, payload);
    }

    let vectors = [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        },
    ];
    let vector_count = if payload.is_empty() { 1 } else { 2 };
    let written = unsafe { libc::writev(fd, vectors.as_ptr(), vector_count) };
    if written < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

fn request_guest_poweroff() -> AgentdResult<()> {
    if crate::handoff::is_pid_1() {
        // PID 1 mode (no handoff): tear down filesystems so block-backed
        // mounts reach a clean terminal state, then power the kernel off.
        crate::teardown::teardown_filesystems(true);
        let ret = unsafe { libc::reboot(libc::RB_POWER_OFF) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        return Ok(());
    }

    unsafe {
        libc::sync();
    }

    // Foreign init owns both shutdown duration and filesystem teardown. No timer or
    // fallback signal may convert this graceful request into forced termination.
    crate::handoff::signal_init_shutdown()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use microsandbox_protocol::message::PROTOCOL_VERSION;

    #[allow(clippy::too_many_arguments)]
    async fn handle_message(
        msg: Message,
        state: &mut AgentState,
        activity: &mut ActivityTracker,
        sender: &mut SessionOutputSender,
        out_buf: &mut Vec<u8>,
        config: &AgentdConfig,
        workload: &mut WorkloadLatch,
        heartbeat: &heartbeat::HeartbeatControl,
    ) -> AgentdResult<()> {
        handle_message_with_charge(
            msg, state, activity, sender, out_buf, config, workload, heartbeat, None,
        )
        .await
    }

    fn decode_reply_skipping_credit(bytes: &mut BytesMut) -> Message {
        loop {
            let Some(DecodedFrame::Control(reply)) =
                codec::try_decode_frame_from_bytes(bytes).unwrap()
            else {
                panic!("missing control reply");
            };
            if reply.t != MessageType::WorkloadTransportCredit {
                return reply;
            }
            assert_eq!(reply.id, u32::MAX);
        }
    }

    #[test]
    fn admitted_transport_window_fits_each_filesystem_input_queue() {
        // Each accepted raw record occupies one queue slot until consumed. Even if one flow
        // receives the whole allowance from both lanes, admission cannot stall the serial actor.
        assert!(
            WORKLOAD_TRANSPORT_CONTROL_FRAMES + WORKLOAD_TRANSPORT_BULK_FRAMES
                <= FS_BULK_INPUT_ITEM_CAPACITY as u64
        );
        assert!(WORKLOAD_TRANSPORT_CONTROL_BYTES <= BULK_INPUT_BYTE_CAPACITY as u64);
        assert!(WORKLOAD_TRANSPORT_BULK_BYTES <= BULK_INPUT_BYTE_CAPACITY as u64);
    }

    #[test]
    fn private_admission_and_credit_batching_use_the_complete_wire_contract() {
        let mut request = Message::with_payload(
            MessageType::WorkloadFreeze,
            u32::MAX,
            &WorkloadFreeze {
                external_mount_tags: Vec::new(),
                attempt_id: "cut".into(),
                host_input: Default::default(),
            },
        )
        .unwrap();
        assert!(private_lifecycle_message(&request));
        request.id = 0;
        assert!(!private_lifecycle_message(&request));
        request.id = u32::MAX;
        request.t = MessageType::ClockSync;
        assert!(!private_lifecycle_message(&request));
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Tcp,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from_static(b"payload"),
        };
        let mut encoded = codec::encode_bulk_header(&record).unwrap().to_vec();
        encoded.extend_from_slice(&record.payload);
        assert_eq!(bulk_wire_bytes(&record, false), encoded.len());
        assert_eq!(
            bulk_wire_bytes(&record, true),
            encoded.len() + CLIENT_INCARNATION_SIZE
        );
        let previous = initial_input_credit();
        let mut current = previous;
        current.control_frames += 15;
        assert!(!input_credit_update_due(&previous, &current));
        current.control_frames += 1;
        assert!(input_credit_update_due(&previous, &current));
        let mut credit = Vec::new();
        encode_input_credit(current, &mut credit).unwrap();
        let mut bytes = BytesMut::from(credit.as_slice());
        let Some(DecodedFrame::Control(reply)) =
            codec::try_decode_frame_from_bytes(&mut bytes).unwrap()
        else {
            panic!()
        };
        assert_eq!(reply.id, u32::MAX);
        assert_eq!(reply.payload::<WorkloadTransportCredit>().unwrap(), current);
        assert!(!guest_message_refreshes_idle_timer(&reply.t));
    }

    #[tokio::test]
    async fn transport_cut_waits_for_decoded_prefix_and_abort_is_owned_and_repeatable() {
        use microsandbox_protocol::core::WorkloadThawMode::{Continue, Restore};
        let mut state = AgentState::default();
        let (mut sender, _output) = SessionOutputSender::channel();
        let mut activity = ActivityTracker::new();
        let config = AgentdConfig {
            user: None,
            security_profile: Default::default(),
            default_cwd: None,
            default_env: Vec::new(),
        };
        let heartbeat = heartbeat::HeartbeatControl::default();
        let mut workload = crate::workload::tests::fake_latch();
        let target = WorkloadTransportPosition {
            bulk_bytes: 80,
            bulk_frames: 1,
            ..Default::default()
        };
        let freeze = || {
            Message::with_payload(
                MessageType::WorkloadFreeze,
                u32::MAX,
                &WorkloadFreeze {
                    external_mount_tags: Vec::new(),
                    attempt_id: "prefix".into(),
                    host_input: target,
                },
            )
            .unwrap()
        };
        for _ in 0..2 {
            let mut out = Vec::new();
            handle_message(
                freeze(),
                &mut state,
                &mut activity,
                &mut sender,
                &mut out,
                &config,
                &mut workload,
                &heartbeat,
            )
            .await
            .unwrap();
            assert!(out.is_empty());
            assert!(!workload.is_frozen());
            assert!(state.pending_freeze.is_some());
        }
        for (attempt, mode, expected) in [
            ("other", Continue, MessageType::CoreError),
            ("prefix", Restore, MessageType::CoreError),
            ("prefix", Continue, MessageType::WorkloadThawed),
            ("prefix", Continue, MessageType::WorkloadThawed),
        ] {
            let thaw = Message::with_payload(
                MessageType::WorkloadThaw,
                u32::MAX,
                &WorkloadThaw {
                    attempt_id: attempt.into(),
                    mode,
                },
            )
            .unwrap();
            let aborts_pending =
                expected == MessageType::WorkloadThawed && state.pending_freeze.is_some();
            let mut out = Vec::new();
            handle_message(
                thaw,
                &mut state,
                &mut activity,
                &mut sender,
                &mut out,
                &config,
                &mut workload,
                &heartbeat,
            )
            .await
            .unwrap();
            let mut bytes = BytesMut::from(out.as_slice());
            if aborts_pending {
                let cancelled = decode_reply_skipping_credit(&mut bytes);
                let error = cancelled.payload::<CoreError>().unwrap();
                assert_eq!(cancelled.id, u32::MAX);
                assert_eq!(
                    error.offending_type.as_deref(),
                    Some(MessageType::WorkloadFreeze.as_str())
                );
                assert_eq!(error.workload_failure.unwrap().attempt_id, "prefix");
            }
            assert_eq!(decode_reply_skipping_credit(&mut bytes).t, expected);
            assert_eq!(
                state.pending_freeze.is_some(),
                expected == MessageType::CoreError
            );
        }
        let charge = state.input_window.admit(InputLane::Bulk, 80).unwrap();
        for _ in 0..2 {
            let mut out = Vec::new();
            handle_message(
                freeze(),
                &mut state,
                &mut activity,
                &mut sender,
                &mut out,
                &config,
                &mut workload,
                &heartbeat,
            )
            .await
            .unwrap();
            let reply = decode_reply_skipping_credit(&mut BytesMut::from(out.as_slice()));
            let frozen = reply.payload::<WorkloadFrozen>().unwrap();
            assert_eq!(reply.t, MessageType::WorkloadFrozen);
            assert!(workload.is_frozen());
            assert!(state.output_parked);
            assert_eq!(
                frozen.input_credit,
                initial_input_credit(),
                "decode is not consumption"
            );
            assert_eq!(state.input_window.position(), target);
        }
        drop(charge);
    }

    #[tokio::test]
    async fn mixed_primary_data_cut_waits_for_the_complete_dedicated_prefix() {
        let mut state = AgentState::default();
        let (mut sender, _output) = SessionOutputSender::channel();
        let mut activity = ActivityTracker::new();
        let config = AgentdConfig {
            user: None,
            security_profile: Default::default(),
            default_cwd: None,
            default_env: Vec::new(),
        };
        let heartbeat = heartbeat::HeartbeatControl::default();
        let mut workload = crate::workload::tests::fake_latch();

        // Primary stdin and its empty EOF share the logical data ledger with the dedicated
        // port. Retain every charge to model a consumer that has not accepted any input yet.
        let mut charges = Vec::new();
        for data in [vec![0x31; 1024], Vec::new()] {
            let message =
                Message::with_payload(MessageType::ExecStdin, 1, &ExecStdin { data }).unwrap();
            assert!(message.t.uses_workload_data_credit());
            let mut wire = Vec::new();
            codec::encode_to_buf(&message, &mut wire).unwrap();
            charges.push(
                state
                    .input_window
                    .admit(InputLane::Bulk, wire.len())
                    .unwrap(),
            );
        }
        let primary_position = state.input_window.position();
        assert_eq!(primary_position.control_bytes, 0);
        assert_eq!(primary_position.control_frames, 0);
        assert_eq!(primary_position.bulk_frames, 2);

        let incarnation = [0x43; CLIENT_INCARNATION_SIZE];
        let record = BulkRecord {
            id: 2,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from(vec![0x52; 512]),
        };
        let mut dedicated_wire = incarnation.to_vec();
        codec::encode_bulk_to_buf(&record, &mut dedicated_wire).unwrap();
        let target = WorkloadTransportPosition {
            bulk_bytes: primary_position.bulk_bytes + dedicated_wire.len() as u64,
            bulk_frames: primary_position.bulk_frames + 1,
            ..primary_position
        };
        let freeze = Message::with_payload(
            MessageType::WorkloadFreeze,
            u32::MAX,
            &WorkloadFreeze {
                external_mount_tags: Vec::new(),
                attempt_id: "mixed-prefix".into(),
                host_input: target,
            },
        )
        .unwrap();

        let mut dedicated_input = BytesMut::new();
        for prefix in [
            &dedicated_wire[..0],
            &dedicated_wire[..dedicated_wire.len() - 1],
        ] {
            dedicated_input.extend_from_slice(prefix);
            assert!(
                try_decode_incarnated_bulk_from_bytes(&mut dedicated_input)
                    .unwrap()
                    .is_none()
            );
            let mut out = Vec::new();
            handle_message(
                freeze.clone(),
                &mut state,
                &mut activity,
                &mut sender,
                &mut out,
                &config,
                &mut workload,
                &heartbeat,
            )
            .await
            .unwrap();
            assert!(
                out.is_empty(),
                "primary data cannot cover missing dedicated bytes"
            );
            assert!(!workload.is_frozen());
            assert!(!state.output_parked);
            assert!(state.pending_freeze.is_some());
            assert_eq!(state.input_window.position(), primary_position);
        }

        dedicated_input.extend_from_slice(&dedicated_wire[dedicated_wire.len() - 1..]);
        let decoded = try_decode_incarnated_bulk_from_bytes(&mut dedicated_input)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.incarnation, incarnation);
        assert_eq!(decoded.record, record);
        assert!(dedicated_input.is_empty());
        charges.push(
            state
                .input_window
                .admit(InputLane::Bulk, bulk_wire_bytes(&decoded.record, true))
                .unwrap(),
        );
        assert_eq!(state.input_window.position(), target);

        // Resume the retained request as the outer actor does once both cumulative counters
        // reach the cut. Decoding suffices; none of the primary or dedicated data is consumed.
        let pending = state.pending_freeze.take().unwrap();
        let mut out = Vec::new();
        handle_message(
            pending,
            &mut state,
            &mut activity,
            &mut sender,
            &mut out,
            &config,
            &mut workload,
            &heartbeat,
        )
        .await
        .unwrap();
        let mut bytes = BytesMut::from(out.as_slice());
        let reply = decode_reply_skipping_credit(&mut bytes);
        let frozen = reply.payload::<WorkloadFrozen>().unwrap();
        assert_eq!(reply.t, MessageType::WorkloadFrozen);
        assert_eq!(reply.id, u32::MAX);
        assert_eq!(frozen.attempt_id, "mixed-prefix");
        assert_eq!(frozen.input_credit, initial_input_credit());
        assert_eq!(state.frozen_host_input, Some(target));
        assert!(workload.is_frozen());
        assert!(state.output_parked);
        assert!(state.pending_freeze.is_none());
        assert!(bytes.is_empty());
        drop(charges);
    }

    #[tokio::test]
    async fn late_tcp_credit_preserves_raw_tail_before_and_after_terminal_retirement() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;

        use microsandbox_protocol::bulk::BulkOffer;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        tokio::time::timeout(Duration::from_secs(10), async {
            let mut state = AgentState::default();
            let incarnation = [0x57; CLIENT_INCARNATION_SIZE];
            establish_relay_client(
                &mut state,
                RelayClientConnected {
                    id_start: 1,
                    id_end_exclusive: microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP,
                    incarnation,
                },
            )
            .unwrap();
            // Leave the dedicated scheduler's input queued: primary completion is allowed to
            // overtake these bytes, but no late credit may send DropFlow to discard their tail.
            let (mut sender, mut control, mut bulk, mut scheduler_commands) =
                SessionOutputSender::split_channel();
            let producer = sender.with_incarnation(Some(incarnation));
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            state.tcp_sessions.insert(
                1,
                TcpSession::open(
                    1,
                    TcpConnect {
                        host: "127.0.0.1".into(),
                        port: listener.local_addr().unwrap().port(),
                        bulk: Some(BulkOffer::tcp()),
                    },
                    &producer,
                ),
            );
            let (mut peer, _) = listener.accept().await.unwrap();
            for expected in [MessageType::TcpConnected, MessageType::BulkAccepted] {
                let envelope = control.recv().await.unwrap();
                let SessionOutput::Raw(mut output) = envelope.output else {
                    panic!()
                };
                assert_eq!(
                    codec::try_decode_from_buf(&mut output.frame)
                        .unwrap()
                        .unwrap()
                        .t,
                    expected
                );
            }
            state
                .tcp_sessions
                .get(&1)
                .unwrap()
                .finish_bulk(BulkFinish {
                    kind: BulkKind::Tcp,
                    flow: BulkFlow::HostToGuest,
                    final_offset: 0,
                })
                .await
                .unwrap();
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
            let payload = Bytes::from(
                (0..6 * 1024 * 1024)
                    .map(|index| (index % 251) as u8)
                    .collect::<Vec<_>>(),
            );
            let peer_payload = payload.clone();
            let peer_task = tokio::spawn(async move {
                peer.write_all(&peer_payload).await.unwrap();
                peer.shutdown().await.unwrap();
            });
            let mut received = Vec::new();
            let mut consumed = 0;
            while consumed < 4 * 1024 * 1024 {
                let envelope = bulk.recv().await.unwrap();
                let SessionOutput::Bulk(output) = &envelope.output else {
                    panic!()
                };
                consumed += output.record.payload.len();
                received.push(envelope);
            }
            peer_task.await.unwrap();
            while !state.tcp_sessions.get(&1).unwrap().is_finished() {
                tokio::task::yield_now().await;
            }
            assert!(consumed < payload.len());
            assert!(
                !bulk.is_empty(),
                "the dedicated output tail must still be queued"
            );
            let credit = BulkCredit {
                kind: BulkKind::Tcp,
                flow: BulkFlow::GuestToHost,
                consumed_offset: consumed as u64,
                credit_limit: consumed as u64 + DEFAULT_BULK_WINDOW,
            };
            let mut activity = ActivityTracker::new();
            let config = AgentdConfig {
                user: None,
                security_profile: Default::default(),
                default_cwd: None,
                default_env: Vec::new(),
            };
            let mut workload = crate::workload::tests::fake_latch();
            let heartbeat = heartbeat::HeartbeatControl::default();
            for retired in [false, true] {
                if retired {
                    for expected in [MessageType::BulkFinish, MessageType::TcpClosed] {
                        let envelope = control.try_recv().unwrap();
                        let SessionOutput::Raw(mut output) = envelope.output else {
                            panic!()
                        };
                        let message = codec::try_decode_from_buf(&mut output.frame)
                            .unwrap()
                            .unwrap();
                        assert_eq!(message.t, expected);
                        if expected == MessageType::BulkFinish {
                            assert_eq!(
                                message.payload::<BulkFinish>().unwrap().final_offset,
                                payload.len() as u64
                            );
                        } else {
                            assert_ne!(
                                message.flags & microsandbox_protocol::message::FLAG_TERMINAL,
                                0
                            );
                            assert!(matches!(output.completion, Some(RawSessionCompletion::Tcp)));
                            complete_raw_session(
                                1,
                                output.completion,
                                &mut state.read_sessions,
                                &mut state.tcp_sessions,
                            );
                            clear_bulk_receive_state(&mut state, 1);
                        }
                    }
                }
                assert_eq!(state.tcp_sessions.contains_key(&1), !retired);
                let mut out = Vec::new();
                handle_message(
                    Message::with_payload(MessageType::BulkCredit, 1, &credit).unwrap(),
                    &mut state,
                    &mut activity,
                    &mut sender,
                    &mut out,
                    &config,
                    &mut workload,
                    &heartbeat,
                )
                .await
                .unwrap();
                assert!(
                    out.is_empty(),
                    "late credit must not emit cancellation or another terminal"
                );
                assert!(
                    matches!(
                        scheduler_commands.try_recv(),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    ),
                    "late credit must not purge raw output"
                );
                assert!(!bulk.is_empty());
            }
            assert!(matches!(
                control.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
            while let Ok(envelope) = bulk.try_recv() {
                received.push(envelope);
            }
            let mut offset = 0;
            let mut actual_hash = DefaultHasher::new();
            let mut expected_hash = DefaultHasher::new();
            expected_hash.write(&payload);
            for envelope in received {
                assert_eq!(envelope.id, 1);
                assert_eq!(envelope.incarnation, Some(incarnation));
                let SessionOutput::Bulk(output) = envelope.output else {
                    panic!()
                };
                let record = output.record;
                assert_eq!(record.offset, offset as u64);
                let end = offset + record.payload.len();
                assert_eq!(record.payload.as_ref(), &payload[offset..end]);
                actual_hash.write(&record.payload);
                offset = end;
            }
            assert_eq!(offset, payload.len());
            assert_eq!(actual_hash.finish(), expected_hash.finish());
        })
        .await
        .expect("late-credit TCP tail did not complete");
    }

    #[tokio::test]
    async fn dedicated_bulk_park_finishes_one_record_and_retains_the_next() {
        use std::os::fd::OwnedFd;
        use tokio::io::AsyncReadExt;

        let (writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        reader.set_nonblocking(true).unwrap();
        let send_buffer: libc::c_int = 4096;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    writer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&send_buffer as *const libc::c_int).cast(),
                    std::mem::size_of_val(&send_buffer) as libc::socklen_t,
                )
            },
            0
        );
        let file = File::from(OwnedFd::from(writer));
        let mut reader = tokio::net::UnixStream::from_std(reader).unwrap();
        let (sender, _control, bulk, commands) = SessionOutputSender::split_channel();
        let (activity, _activities) = tokio::sync::mpsc::channel(8);
        let writer = tokio::spawn(bulk_writer_task(file, bulk, commands, activity));
        let sender = sender.with_incarnation(Some([0x62; CLIENT_INCARNATION_SIZE]));
        let first = BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from(vec![0x6a; 1024 * 1024]),
        };
        let first_len = bulk_wire_bytes(&first, true);
        let second = BulkRecord {
            offset: first.payload.len() as u64,
            payload: Bytes::from_static(b"next"),
            ..first.clone()
        };
        let second_len = bulk_wire_bytes(&second, true);
        for record in [first, second] {
            assert!(
                sender
                    .send(
                        1,
                        SessionOutput::Bulk(crate::session::BulkSessionOutput::new(
                            record,
                            RawActivity::default()
                        ))
                    )
                    .await
            );
        }
        let mut bytes = vec![0; first_len];
        time::timeout(Duration::from_secs(5), reader.read_exact(&mut bytes[..37]))
            .await
            .unwrap()
            .unwrap();
        let park_sender = sender.clone();
        let mut park = tokio::spawn(async move { park_sender.park_bulk_output().await });
        assert!(
            time::timeout(Duration::from_millis(20), &mut park)
                .await
                .is_err(),
            "park cut a partial record"
        );
        time::timeout(Duration::from_secs(5), reader.read_exact(&mut bytes[37..]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            time::timeout(Duration::from_secs(5), park)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            first_len as u64
        );
        let mut decoded = BytesMut::from(bytes.as_slice());
        let frame = try_decode_incarnated_bulk_from_bytes(&mut decoded)
            .unwrap()
            .unwrap();
        assert_eq!(frame.record.payload, Bytes::from(vec![0x6a; 1024 * 1024]));
        assert!(decoded.is_empty());
        assert!(
            time::timeout(Duration::from_millis(20), reader.read(&mut [0; 1]))
                .await
                .is_err()
        );
        sender.resume_bulk_output().await.unwrap();
        let mut bytes = vec![0; second_len];
        time::timeout(Duration::from_secs(5), reader.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sender.park_bulk_output().await.unwrap(),
            (first_len + second_len) as u64
        );
        writer.abort();
        let _ = writer.await;
    }

    #[test]
    fn coalesced_bootstrap_and_init_ack_retain_the_second_frame() {
        let bootstrap = GuestBootstrap::default();
        let bootstrap_message =
            Message::with_payload(MessageType::Bootstrap, 0, &bootstrap).unwrap();
        let ack_message = Message::with_payload(MessageType::InitAck, 0, &InitAck {}).unwrap();
        let mut state = BootConsoleState::default();
        codec::encode_to_buf(&bootstrap_message, &mut state.input).unwrap();
        codec::encode_to_buf(&ack_message, &mut state.input).unwrap();

        let decoded = read_boot_message(
            -1,
            &mut state,
            Instant::now() + std::time::Duration::from_secs(1),
            "guest bootstrap",
        )
        .unwrap();
        assert_eq!(decode_bootstrap_message(decoded).unwrap(), bootstrap);
        assert!(
            !state.input.is_empty(),
            "init ack frame should remain buffered"
        );

        wait_for_init_ack(
            -1,
            &mut state,
            Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert!(state.input.is_empty());
    }

    #[test]
    fn bootstrap_rejects_non_control_correlation_fields() {
        let mut message =
            Message::with_payload(MessageType::Bootstrap, 1, &GuestBootstrap::default()).unwrap();
        message.flags = 1;

        let error = decode_bootstrap_message(message).unwrap_err();
        assert!(error.to_string().contains("requires id=0 and flags=0"));
    }

    #[test]
    fn bootstrap_rejects_wrong_first_message_type() {
        let message = Message::with_payload(MessageType::Ping, 0, &Ping {}).unwrap();

        let error = decode_bootstrap_message(message).unwrap_err();
        assert!(error.to_string().contains("expected core.bootstrap"));
    }

    #[test]
    fn bootstrap_rejects_older_protocol_generation() {
        let mut message =
            Message::with_payload(MessageType::Bootstrap, 0, &GuestBootstrap::default()).unwrap();
        let min_version = MessageType::Bootstrap.min_protocol_version();
        assert!(min_version > 0);
        message.v = min_version - 1;

        let error = decode_bootstrap_message(message).unwrap_err();
        assert!(error.to_string().contains("or newer"));
    }

    #[test]
    fn bootstrap_accepts_minimum_supported_protocol_generation() {
        let mut message =
            Message::with_payload(MessageType::Bootstrap, 0, &GuestBootstrap::default()).unwrap();
        message.v = MessageType::Bootstrap.min_protocol_version();

        assert_eq!(
            decode_bootstrap_message(message).unwrap(),
            GuestBootstrap::default()
        );
    }

    #[test]
    fn bootstrap_accepts_newer_additive_protocol_generation() {
        let mut message =
            Message::with_payload(MessageType::Bootstrap, 0, &GuestBootstrap::default()).unwrap();
        message.v = PROTOCOL_VERSION + 1;

        assert_eq!(
            decode_bootstrap_message(message).unwrap(),
            GuestBootstrap::default()
        );
    }

    #[test]
    fn bootstrap_rejects_malformed_payload() {
        let message = Message::new(MessageType::Bootstrap, 0, vec![0xff]);

        let error = decode_bootstrap_message(message).unwrap_err();
        assert!(error.to_string().contains("decode guest bootstrap payload"));
    }
    #[test]
    fn dual_port_cmdline_hint_requires_an_exact_argument() {
        assert!(cmdline_requests_dual_port(
            "console=hvc0 microsandbox.agent_transport=dual-port-v1 quiet"
        ));
        assert!(!cmdline_requests_dual_port(
            "microsandbox.agent_transport=dual-port-v10"
        ));
        assert!(!cmdline_requests_dual_port(
            "prefix=microsandbox.agent_transport=dual-port-v1"
        ));
    }

    #[test]
    fn primary_read_buffer_tracks_whether_it_carries_bulk() {
        assert_eq!(
            primary_serial_read_buf_size(false),
            COMBINED_SERIAL_READ_BUF_SIZE
        );
        assert_eq!(
            primary_serial_read_buf_size(true),
            CONTROL_SERIAL_READ_BUF_SIZE
        );
    }

    #[test]
    fn bulk_reader_turn_is_bounded_by_records_or_payload_bytes() {
        assert!(!bulk_reader_turn_exhausted(1, 1));
        assert!(bulk_reader_turn_exhausted(
            BULK_READER_MAX_RECORDS_PER_TURN,
            1
        ));
        assert!(bulk_reader_turn_exhausted(
            1,
            BULK_READER_MAX_BYTES_PER_TURN
        ));
    }

    #[test]
    fn agent_read_budget_counts_bytes_and_calls_independently() {
        let mut bytes = AgentReadBudget::default();
        bytes.record_read(AGENT_READ_QUANTUM_BYTES - 1);
        assert!(!bytes.exhausted());
        bytes.record_read(1);
        assert!(bytes.exhausted());

        let mut calls = AgentReadBudget::default();
        for _ in 1..AGENT_READ_QUANTUM_CALLS {
            assert!(calls.read_fd(-1, &mut [0]).is_err());
            assert!(!calls.exhausted());
        }
        assert!(calls.read_fd(-1, &mut [0]).is_err());
        assert!(calls.exhausted(), "failed reads also bound a retry loop");
        assert_eq!(calls.bytes, 0);

        let mut large = AgentReadBudget::default();
        large.record_read(BULK_SERIAL_READ_BUF_SIZE);
        assert!(
            large.exhausted(),
            "a large read is not a smaller wire record"
        );
        assert_eq!(large.bytes, BULK_SERIAL_READ_BUF_SIZE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_read_budget_services_driver_during_partial_bulk_records() {
        // The control demonstrates the failure without relying on wall-clock delays: cached
        // readable bulk input never lets the runtime observe the newly readable/writable peers.
        assert!(!observe_driver_during_partial_bulk(false).await);
        assert!(observe_driver_during_partial_bulk(true).await);
    }

    async fn observe_driver_during_partial_bulk(yield_at_boundary: bool) -> bool {
        use std::io::Write;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::AtomicUsize;

        let incarnation = [0x42; CLIENT_INCARNATION_SIZE];
        let first = BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from(vec![0xa5; 512]),
        };
        let second = BulkRecord {
            offset: first.payload.len() as u64,
            payload: Bytes::from(vec![0x5a; 512]),
            ..first.clone()
        };
        let mut wire = Vec::new();
        for record in [&first, &second] {
            wire.extend_from_slice(&incarnation);
            codec::encode_bulk_to_buf(record, &mut wire).unwrap();
        }
        let (mut source, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        source.write_all(&wire).unwrap();
        let mut input = BulkInputState::new(File::from(OwnedFd::from(input))).unwrap();
        // Model fragmented console reads while keeping the complete wire records unchanged.
        input.read_buf.truncate(1);

        let (mut control_source, control) = UnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        let control = AsyncFd::new(control).unwrap();
        let (pipe_reader, pipe_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_NONBLOCK).unwrap();
        let pipe_writer = AsyncFd::new(pipe_writer).unwrap();
        // Prime the reactor, then clear the pipe's cached writable event with a real EAGAIN.
        let mut writable = pipe_writer.writable().await.unwrap();
        loop {
            match writable.try_io(|fd| write_to_fd(fd.get_ref().as_raw_fd(), &[0; 4096])) {
                Ok(Ok(count)) => assert!(count > 0),
                Ok(Err(error)) => panic!("fill stdin pipe: {error}"),
                Err(_) => break,
            }
        }
        drop(writable);
        let mut drained = [0; 4096];
        loop {
            match read_from_fd(pipe_reader.as_raw_fd(), &mut drained) {
                Ok(count) => assert!(count > 0),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("drain stdin pipe: {error}"),
            }
        }
        control_source.write_all(b"c").unwrap();
        let serviced = Arc::new(AtomicUsize::new(0));
        let control_serviced = Arc::clone(&serviced);
        let control_task = tokio::spawn(async move {
            loop {
                let mut ready = control.readable().await.unwrap();
                let mut byte = [0];
                match ready.try_io(|fd| read_from_fd(fd.get_ref().as_raw_fd(), &mut byte)) {
                    Ok(Ok(1)) => {
                        assert_eq!(byte, *b"c");
                        control_serviced.fetch_or(1, Ordering::Relaxed);
                        break;
                    }
                    Ok(result) => panic!("read control marker: {result:?}"),
                    Err(_) => continue,
                }
            }
        });
        let stdin_serviced = Arc::clone(&serviced);
        let stdin_task = tokio::spawn(async move {
            std::future::poll_fn(|cx| {
                loop {
                    let mut ready = std::task::ready!(pipe_writer.poll_write_ready(cx)).unwrap();
                    match ready.try_io(|fd| write_to_fd(fd.get_ref().as_raw_fd(), b"i")) {
                        Ok(result) => return Poll::Ready(result),
                        Err(_) => continue,
                    }
                }
            })
            .await
            .unwrap();
            stdin_serviced.fetch_or(2, Ordering::Relaxed);
        });

        let mut budget = AgentReadBudget::default();
        let mut received = Vec::new();
        let mut serviced_before_first_record = false;
        while received.len() < 2 {
            let frames = tokio::select! {
                frames = input.read_turn(&mut budget) => frames.unwrap(),
                _ = std::future::pending::<()>() => unreachable!(),
            };
            for frame in frames {
                assert_eq!(frame.incarnation, incarnation);
                received.push(frame.record);
            }
            // This is the production cancellation-safe boundary: no decoded frames are local to
            // a competing select future, and even partial-record reads have spent the budget.
            if yield_at_boundary {
                budget.yield_if_exhausted().await;
            }
            if received.is_empty() && serviced.load(Ordering::Relaxed) == 3 {
                serviced_before_first_record = true;
            }
        }
        assert_eq!(
            received,
            [first, second],
            "yield preserves record bytes and FIFO"
        );
        assert!(input.input.is_empty());
        control_task.await.unwrap();
        stdin_task.await.unwrap();
        let mut marker = [0];
        assert_eq!(
            read_from_fd(pipe_reader.as_raw_fd(), &mut marker).unwrap(),
            1
        );
        assert_eq!(marker, *b"i");
        serviced_before_first_record
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_bulk_read_keeps_partial_record_and_read_budget() {
        use std::io::Write;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;

        let incarnation = [0x29; CLIENT_INCARNATION_SIZE];
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from(vec![0x51; 512]),
        };
        let mut wire = incarnation.to_vec();
        codec::encode_bulk_to_buf(&record, &mut wire).unwrap();
        let (mut source, input) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        let mut input = BulkInputState::new(File::from(OwnedFd::from(input))).unwrap();
        let mut budget = AgentReadBudget::default();
        source.write_all(&wire[..40]).unwrap();
        assert!(input.read_turn(&mut budget).await.unwrap().is_empty());
        // Consume the stale readable hint so the following select truly cancels a pending read.
        assert!(input.read_turn(&mut budget).await.unwrap().is_empty());
        let calls = budget.calls;
        tokio::select! {
            biased;
            result = input.read_turn(&mut budget) => panic!("unexpected read: {result:?}"),
            _ = std::future::ready(()) => {},
        }
        assert_eq!(input.input.as_ref(), &wire[..40]);
        assert_eq!(budget.bytes, 40);
        assert_eq!(budget.calls, calls);
        source.write_all(&wire[40..]).unwrap();
        let frames = input.read_turn(&mut budget).await.unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].record, record);
        assert_eq!(frames[0].incarnation, incarnation);
        assert!(input.input.is_empty());
        assert_eq!(budget.bytes, wire.len());
    }

    #[test]
    fn disconnect_cleanup_keeps_other_clients_bulk_offsets() {
        let mut state = AgentState::default();
        for id in [1, 10, 20] {
            state.bulk_received_offsets.insert(id, id as u64);
            state.pending_bulk_finishes.insert(
                id,
                BulkFinish {
                    kind: BulkKind::Filesystem,
                    flow: BulkFlow::HostToGuest,
                    final_offset: id as u64,
                },
            );
        }

        clear_bulk_receive_range(&mut state, 10, 20);

        assert_eq!(state.bulk_received_offsets.len(), 2);
        assert!(state.bulk_received_offsets.contains_key(&1));
        assert!(state.bulk_received_offsets.contains_key(&20));
        assert_eq!(state.pending_bulk_finishes.len(), 2);
        assert!(state.pending_bulk_finishes.contains_key(&1));
        assert!(state.pending_bulk_finishes.contains_key(&20));
    }

    #[test]
    fn recycled_range_rejects_old_incarnation_and_stale_disconnect() {
        let id_start = 1;
        let id_end_exclusive = microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP;
        let old = [0x11; CLIENT_INCARNATION_SIZE];
        let new = [0x22; CLIENT_INCARNATION_SIZE];
        let mut state = AgentState::default();

        establish_relay_client(
            &mut state,
            RelayClientConnected {
                id_start,
                id_end_exclusive,
                incarnation: old,
            },
        )
        .unwrap();
        state.bulk_received_offsets.insert(id_start, 4096);
        let (session_tx, _session_rx) = SessionOutputSender::channel();
        let (removed, cleanup) = disconnect_relay_client(
            &mut state,
            RelayClientDisconnected {
                id_start,
                id_end_exclusive,
                incarnation: Some(old),
            },
            &session_tx,
        )
        .unwrap();
        assert!(removed);
        assert!(cleanup.is_none());
        establish_relay_client(
            &mut state,
            RelayClientConnected {
                id_start,
                id_end_exclusive,
                incarnation: new,
            },
        )
        .unwrap();

        assert_eq!(client_incarnation_for_id(&state, id_start), Some(new));
        assert!(validate_bulk_client_incarnation(&state, id_start, new).unwrap());
        assert!(!validate_bulk_client_incarnation(&state, id_start, old).unwrap());

        let other_start = microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP + 1;
        let other_end = microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP * 2;
        establish_relay_client(
            &mut state,
            RelayClientConnected {
                id_start: other_start,
                id_end_exclusive: other_end,
                incarnation: [0x33; CLIENT_INCARNATION_SIZE],
            },
        )
        .unwrap();
        assert!(validate_bulk_client_incarnation(&state, other_start, new).is_err());
        assert!(!state.bulk_received_offsets.contains_key(&id_start));
        assert!(
            !disconnect_relay_client(
                &mut state,
                RelayClientDisconnected {
                    id_start,
                    id_end_exclusive,
                    incarnation: Some(old),
                },
                &session_tx,
            )
            .unwrap()
            .0
        );
        assert_eq!(client_incarnation_for_id(&state, id_start), Some(new));
    }

    #[test]
    fn aggregate_bulk_input_budget_is_bounded_and_recoverable() {
        let state = AgentState::default();
        let budget = state.bulk_input_budget;
        let held = Arc::clone(&budget)
            .try_acquire_many_owned(BULK_INPUT_BYTE_CAPACITY as u32)
            .unwrap();

        assert!(Arc::clone(&budget).try_acquire_owned().is_err());
        drop(held);
        assert_eq!(budget.available_permits(), BULK_INPUT_BYTE_CAPACITY);
    }

    #[test]
    fn disconnect_ack_does_not_refresh_idle_activity() {
        let ack = encode_relay_client_disconnected_ack(RelayClientDisconnectedAck {
            id_start: 1,
            id_end_exclusive: microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP,
            incarnation: [0x4a; CLIENT_INCARNATION_SIZE],
        });
        assert!(!encoded_guest_message_refreshes_idle_timer(
            &ack,
            0,
            ack.len() - 4,
        ));
    }

    #[tokio::test]
    async fn closed_optional_receiver_disables_itself_without_spinning() {
        let (tx, rx) = tokio::sync::mpsc::channel::<u8>(1);
        drop(tx);
        let mut receiver = Some(rx);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), recv_optional(&mut receiver))
                .await
                .is_err()
        );
        assert!(receiver.is_none());
    }

    #[tokio::test]
    async fn bulk_output_tombstone_discards_late_producer_record() {
        let incarnation = [0x5a; CLIENT_INCARNATION_SIZE];
        let (session_tx, _control_rx, mut bulk_rx, _command_rx) =
            SessionOutputSender::split_channel();
        let owner_tx = session_tx.with_incarnation(Some(incarnation));
        let record = || BulkRecord {
            id: 17,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: bytes::Bytes::from_static(b"late"),
        };
        assert!(
            owner_tx
                .send(
                    17,
                    SessionOutput::Bulk(crate::session::BulkSessionOutput::new(
                        record(),
                        RawActivity::default(),
                    )),
                )
                .await
        );

        let mut generation = 0;
        let mut flows = HashMap::new();
        let mut active = VecDeque::new();
        let mut retired = HashMap::new();
        let mut retiring_incarnations = HashSet::new();
        enqueue_bulk_output(
            bulk_rx.recv().await.unwrap(),
            0,
            &mut flows,
            &mut active,
            &retired,
            &retiring_incarnations,
        )
        .unwrap();
        let (completion, mut completed) = tokio::sync::oneshot::channel();
        let cleanup = apply_bulk_output_command(
            BulkOutputCommand::DropFlow {
                incarnation,
                id: 17,
                completion,
            },
            &mut generation,
            &mut flows,
            &mut active,
            &mut retired,
            &mut retiring_incarnations,
            &mut BulkOutputPosition::default(),
        )
        .unwrap();
        assert!(matches!(
            completed.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        complete_bulk_output_cleanups(vec![cleanup], &mut retired, &mut retiring_incarnations);
        assert_eq!(completed.try_recv(), Ok(()));

        assert!(
            owner_tx
                .send(
                    17,
                    SessionOutput::Bulk(crate::session::BulkSessionOutput::new(
                        record(),
                        RawActivity::default(),
                    )),
                )
                .await
        );
        enqueue_bulk_output(
            bulk_rx.recv().await.unwrap(),
            0,
            &mut flows,
            &mut active,
            &retired,
            &retiring_incarnations,
        )
        .unwrap();

        assert!(flows.is_empty());
        assert!(active.is_empty());
        assert!(bulk_output_is_retired(&retired, incarnation, 17));
    }

    #[test]
    fn record_encoded_guest_messages_counts_only_appended_frames() {
        let mut out_buf = Vec::new();
        let existing =
            Message::with_payload(MessageType::ExecStarted, 1, &ExecStarted { pid: 123 }).unwrap();
        codec::encode_to_buf(&existing, &mut out_buf).unwrap();
        let start = out_buf.len();

        let appended =
            Message::with_payload(MessageType::ExecStarted, 2, &ExecStarted { pid: 456 }).unwrap();
        codec::encode_to_buf(&appended, &mut out_buf).unwrap();

        let mut activity = ActivityTracker::new();
        record_encoded_guest_messages(&out_buf, start, &mut activity);

        assert_eq!(activity.activity_seq, 1);
        assert_eq!(activity.counters.guest_messages, 1);
    }

    #[test]
    fn apply_raw_activity_updates_guest_and_byte_counters() {
        let mut activity = ActivityTracker::new();

        apply_raw_activity(RawActivity::fs_bytes(42), &mut activity);
        apply_raw_activity(RawActivity::tcp_bytes(7), &mut activity);

        assert_eq!(activity.activity_seq, 2);
        assert_eq!(activity.counters.guest_messages, 2);
        assert_eq!(activity.counters.fs_bytes, 42);
        assert_eq!(activity.counters.tcp_bytes, 7);
    }

    #[test]
    fn apply_raw_activity_preserves_coalesced_message_count() {
        let mut activity = ActivityTracker::new();

        apply_raw_activity(
            RawActivity {
                guest_messages: 16,
                fs_bytes: 4 * 1024 * 1024,
                tcp_bytes: 0,
            },
            &mut activity,
        );

        assert_eq!(activity.activity_seq, 16);
        assert_eq!(activity.counters.guest_messages, 16);
        assert_eq!(activity.counters.fs_bytes, 4 * 1024 * 1024);
    }

    #[tokio::test]
    async fn filesystem_finish_remains_admissible_after_a_full_data_window() {
        let (records, _record_rx) = tokio::sync::mpsc::channel(FS_BULK_INPUT_ITEM_CAPACITY);
        let (finish, mut finish_rx) = tokio::sync::mpsc::channel(1);
        let worker = FsBulkWriteWorker {
            records,
            finish,
            task: tokio::spawn(std::future::pending::<()>()),
        };
        let payload = Bytes::from(vec![0u8; MIN_BULK_RECORD_PAYLOAD as usize]);

        for index in 0..FS_BULK_INPUT_ITEM_CAPACITY {
            worker
                .records
                .try_send(AdmittedBulkRecord::for_test(BulkRecord {
                    id: 17,
                    kind: BulkKind::Filesystem,
                    flow: BulkFlow::HostToGuest,
                    offset: (index * MIN_BULK_RECORD_PAYLOAD as usize) as u64,
                    payload: payload.clone(),
                }))
                .unwrap();
        }
        assert_eq!(worker.records.capacity(), 0);

        let expected = BulkFinish {
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            final_offset: microsandbox_protocol::bulk::DEFAULT_BULK_WINDOW,
        };
        worker.finish.try_send(expected).unwrap();
        assert_eq!(finish_rx.recv().await, Some(expected));
        worker.task.abort();
    }

    #[test]
    fn maintenance_messages_do_not_implicitly_refresh_idle_timer() {
        assert!(!message_refreshes_idle_timer(&MessageType::ClockSync));
        assert!(!message_refreshes_idle_timer(&MessageType::Ping));
        assert!(!message_refreshes_idle_timer(&MessageType::Touch));
        assert!(message_refreshes_idle_timer(&MessageType::ExecRequest));
    }

    #[test]
    fn maintenance_replies_do_not_refresh_idle_timer() {
        assert!(!guest_message_refreshes_idle_timer(&MessageType::Pong));
        assert!(!guest_message_refreshes_idle_timer(&MessageType::Touched));
        assert!(!guest_message_refreshes_idle_timer(&MessageType::CoreError));
        assert!(guest_message_refreshes_idle_timer(&MessageType::ExecStdout));
    }

    #[test]
    fn record_encoded_guest_messages_ignores_pong_and_touched() {
        let mut out_buf = Vec::new();
        let pong = Message::with_payload(MessageType::Pong, 1, &Pong {}).unwrap();
        codec::encode_to_buf(&pong, &mut out_buf).unwrap();

        let touched =
            Message::with_payload(MessageType::Touched, 2, &Touched { activity_seq: 42 }).unwrap();
        codec::encode_to_buf(&touched, &mut out_buf).unwrap();

        let mut activity = ActivityTracker::new();
        record_encoded_guest_messages(&out_buf, 0, &mut activity);

        assert_eq!(activity.activity_seq, 0);
        assert_eq!(activity.counters.guest_messages, 0);
    }

    #[test]
    fn bulk_cancellation_uses_each_operations_existing_terminal_type() {
        for (kind, expected) in [
            (BulkKind::Filesystem, MessageType::FsResponse),
            (BulkKind::Tcp, MessageType::TcpFailed),
        ] {
            let mut encoded = Vec::new();
            encode_bulk_terminal_failure(17, kind, "cancelled".into(), &mut encoded).unwrap();
            let mut bytes = BytesMut::from(encoded.as_slice());
            let frame = codec::try_decode_frame_from_bytes(&mut bytes)
                .unwrap()
                .expect("terminal frame");
            let DecodedFrame::Control(message) = frame else {
                panic!("cancellation terminal must be control");
            };
            assert_eq!(message.id, 17);
            assert_eq!(message.t, expected);
            assert_eq!(message.flags, microsandbox_protocol::message::FLAG_TERMINAL);
            assert!(bytes.is_empty());
        }
    }
    #[tokio::test]
    async fn restore_thaw_checks_ownership_is_idempotent_and_leaves_source_clients_alone() {
        use microsandbox_protocol::core::WorkloadThawMode;

        let mut state = AgentState::default();
        let (mut sender, _output) = SessionOutputSender::channel();
        let mut activity = ActivityTracker::new();
        let heartbeat = heartbeat::HeartbeatControl::default();
        let config = AgentdConfig {
            user: None,
            security_profile: Default::default(),
            default_cwd: None,
            default_env: Vec::new(),
        };
        let mut workload = crate::workload::tests::fake_latch();
        let owner = [0x51; CLIENT_INCARNATION_SIZE];
        let connect = |state: &mut AgentState| {
            establish_relay_client(
                state,
                RelayClientConnected {
                    id_start: 1,
                    id_end_exclusive: microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP,
                    incarnation: owner,
                },
            )
            .unwrap();
        };
        connect(&mut state);
        workload.freeze("capture").unwrap();

        // Wrong attempts cannot detach a client's state. Source-side thaw must also preserve it.
        for (attempt, mode, expected) in [
            ("wrong", WorkloadThawMode::Restore, MessageType::CoreError),
            (
                "capture",
                WorkloadThawMode::Continue,
                MessageType::WorkloadThawed,
            ),
        ] {
            let request = Message::with_payload(
                MessageType::WorkloadThaw,
                0,
                &WorkloadThaw {
                    attempt_id: attempt.into(),
                    mode,
                },
            )
            .unwrap();
            let mut encoded = Vec::new();
            handle_message(
                request,
                &mut state,
                &mut activity,
                &mut sender,
                &mut encoded,
                &config,
                &mut workload,
                &heartbeat,
            )
            .await
            .unwrap();
            let mut bytes = BytesMut::from(encoded.as_slice());
            let reply = decode_reply_skipping_credit(&mut bytes);
            assert_eq!(reply.t, expected);
            assert_eq!(sender.generation(), 0);
            assert_eq!(client_incarnation_for_id(&state, 1), Some(owner));
        }

        for generation in 1..=2 {
            // Reuse the same human-readable name for a subsequent capture, then retry its thaw.
            let request = Message::with_payload(
                MessageType::WorkloadFreeze,
                0,
                &WorkloadFreeze {
                    external_mount_tags: Vec::new(),
                    attempt_id: "capture".into(),
                    host_input: WorkloadTransportPosition::default(),
                },
            )
            .unwrap();
            handle_message(
                request,
                &mut state,
                &mut activity,
                &mut sender,
                &mut Vec::new(),
                &config,
                &mut workload,
                &heartbeat,
            )
            .await
            .unwrap();
            for retry in [false, true] {
                let request = Message::with_payload(
                    MessageType::WorkloadThaw,
                    0,
                    &WorkloadThaw {
                        attempt_id: "capture".into(),
                        mode: WorkloadThawMode::Restore,
                    },
                )
                .unwrap();
                let mut encoded = Vec::new();
                handle_message(
                    request,
                    &mut state,
                    &mut activity,
                    &mut sender,
                    &mut encoded,
                    &config,
                    &mut workload,
                    &heartbeat,
                )
                .await
                .unwrap();
                let mut bytes = BytesMut::from(encoded.as_slice());
                let reply = decode_reply_skipping_credit(&mut bytes);
                assert_eq!(reply.t, MessageType::WorkloadThawed);
                assert!(!workload.is_frozen());
                assert_eq!(sender.generation(), generation);
                assert_eq!(client_incarnation_for_id(&state, 1), retry.then_some(owner));
                if !retry {
                    // A retry must not detach clients which connected after the first success.
                    connect(&mut state);
                }
            }
        }
    }

    #[tokio::test]
    async fn saturated_stdin_allows_thaw_and_preserves_input_and_eof() {
        use microsandbox_protocol::core::WorkloadThawMode::{Continue, Restore};

        // SIGSTOP provides a deterministic blocked pipe/PTY without a privileged cgroup mount.
        // Thaw must complete before external consumer progress, then accepted data drains exactly
        // once. Restore closes inherited pipe input after data even when no EOF was accepted.
        struct StoppedProcessGuard(i32);
        impl Drop for StoppedProcessGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(-self.0, libc::SIGCONT);
                    libc::kill(-self.0, libc::SIGKILL);
                }
            }
        }

        for (tty, mode, accepted_eof) in [
            (false, Continue, false),
            (false, Continue, true),
            (false, Restore, false),
            (false, Restore, true),
            (true, Continue, true),
            (true, Restore, true),
        ] {
            let mut state = AgentState::default();
            let (mut sender, mut output) = SessionOutputSender::channel();
            let mut activity = ActivityTracker::new();
            let heartbeat = heartbeat::HeartbeatControl::default();
            let config = AgentdConfig {
                user: None,
                security_profile: Default::default(),
                default_cwd: None,
                default_env: Vec::new(),
            };
            let mut workload = crate::workload::tests::fake_latch();
            workload.freeze("stdin-cut").unwrap();
            let request = ExecRequest {
                cmd: "/bin/sh".into(),
                args: vec![
                    "-c".into(),
                    if tty {
                        "stty raw -echo; kill -STOP $$; exec cat"
                    } else {
                        "kill -STOP $$; exec cat"
                    }
                    .into(),
                ],
                env: vec![],
                cwd: None,
                user: None,
                tty,
                rows: 24,
                cols: 80,
                rlimits: vec![],
            };
            let session = ExecSession::spawn(
                1,
                &request,
                sender.clone(),
                None,
                crate::config::SecurityProfile::Default,
                None,
            )
            .unwrap();
            let pid = session.pid() as i32;
            state.sessions.insert(1, session);
            let _cleanup = StoppedProcessGuard(pid);
            time::timeout(Duration::from_secs(5), async {
                loop {
                    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
                    if status.lines().any(|line| line.starts_with("State:\tT")) {
                        break;
                    }
                    time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("workload should stop before stdin is admitted");

            let mut encoded = Vec::new();
            let ledger = state.input_window.clone();
            let initial = ledger.credit().unwrap();
            let data = vec![0x61; 1024 * 1024];
            let charge = ledger.admit(InputLane::Bulk, data.len() + 32).unwrap();
            let mut stdin =
                Message::with_payload(MessageType::ExecStdin, 1, &ExecStdin { data }).unwrap();
            // A generation-8 SDK still travels over the bundled private transport contract.
            // Dispatch must not fall back to blocking writes based on the client message version.
            stdin.v = 8;
            time::timeout(
                Duration::from_millis(100),
                handle_message_with_charge(
                    stdin,
                    &mut state,
                    &mut activity,
                    &mut sender,
                    &mut encoded,
                    &config,
                    &mut workload,
                    &heartbeat,
                    Some(charge),
                ),
            )
            .await
            .expect("stdin dispatch waited on its blocked consumer")
            .unwrap();
            assert!(encoded.is_empty());
            assert!(state.sessions[&1].has_pending_stdin());
            if accepted_eof {
                let charge = ledger.admit(InputLane::Bulk, 32).unwrap();
                let mut eof = Message::with_payload(
                    MessageType::ExecStdin,
                    1,
                    &ExecStdin { data: Vec::new() },
                )
                .unwrap();
                eof.v = 8;
                time::timeout(
                    Duration::from_millis(100),
                    handle_message_with_charge(
                        eof,
                        &mut state,
                        &mut activity,
                        &mut sender,
                        &mut encoded,
                        &config,
                        &mut workload,
                        &heartbeat,
                        Some(charge),
                    ),
                )
                .await
                .expect("EOF dispatch waited on preceding blocked data")
                .unwrap();
            }
            assert_eq!(
                ledger.credit().unwrap(),
                initial,
                "blocked input refunded before consumption"
            );
            let position = ledger.position();
            let thaw = Message::with_payload(
                MessageType::WorkloadThaw,
                u32::MAX,
                &WorkloadThaw {
                    attempt_id: "stdin-cut".into(),
                    mode,
                },
            )
            .unwrap();
            time::timeout(
                Duration::from_millis(100),
                handle_message(
                    thaw,
                    &mut state,
                    &mut activity,
                    &mut sender,
                    &mut encoded,
                    &config,
                    &mut workload,
                    &heartbeat,
                ),
            )
            .await
            .expect("thaw waited on saturated stdin")
            .unwrap();
            assert!(!workload.is_frozen());
            let mut bytes = BytesMut::from(encoded.as_slice());
            let reply = decode_reply_skipping_credit(&mut bytes);
            assert_eq!(reply.t, MessageType::WorkloadThawed);
            assert_eq!(
                ledger.position(),
                position,
                "restore reset cumulative input position"
            );
            assert_eq!(
                ledger.credit().unwrap(),
                initial,
                "restore discarded accepted input"
            );
            assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
            let mut received = Vec::new();
            let mut exited = false;
            time::timeout(Duration::from_secs(5), async {
                while received.len() < 1024 * 1024
                    || state.sessions.values().chain(state.detached_sessions.values()).any(ExecSession::has_pending_stdin)
                    || (!tty && (accepted_eof || mode == Restore) && !exited) {
                    tokio::select! {
                        (_, _, result) = std::future::poll_fn(|cx| poll_pending_stdin(&mut state, cx)) => result.unwrap(),
                        envelope = output.recv() => match envelope.unwrap().output {
                            SessionOutput::Stdout(data) => received.extend(data),
                            SessionOutput::Exited(code) => { assert_eq!(code, 0); exited = true; },
                            _ => {},
                        },
                    }
                }
            })
            .await
            .expect("accepted stdin or ordered EOF did not drain");
            assert_eq!(received, vec![0x61; 1024 * 1024]);
            assert_eq!(
                ledger.credit().unwrap().bulk_bytes,
                initial.bulk_bytes + position.bulk_bytes
            );
            if !tty && mode == Continue && !accepted_eof {
                // Source Continue must not synthesize EOF. The same owner can still send input.
                assert!(!exited);
                state
                    .sessions
                    .get_mut(&1)
                    .unwrap()
                    .enqueue_stdin(b"tail".to_vec(), None)
                    .unwrap();
                let envelope = time::timeout(Duration::from_secs(5), output.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    matches!(envelope.output, SessionOutput::Stdout(ref data) if data == b"tail")
                );
            }
        }
    }

    #[tokio::test]
    async fn restore_detaches_piped_and_pty_workloads_without_killing_or_reusing_output() {
        for tty in [false, true] {
            let mut state = AgentState::default();
            let (mut sender, mut output) = SessionOutputSender::channel();
            let id = 1;
            let end = microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP;
            let old_owner = [0x31; CLIENT_INCARNATION_SIZE];
            let new_owner = [0x32; CLIENT_INCARNATION_SIZE];
            establish_relay_client(
                &mut state,
                RelayClientConnected {
                    id_start: id,
                    id_end_exclusive: end,
                    incarnation: old_owner,
                },
            )
            .unwrap();
            let request = |script: &str| ExecRequest {
                cmd: "/bin/sh".into(),
                args: vec!["-c".into(), script.into()],
                env: vec![],
                cwd: None,
                user: None,
                tty,
                rows: 24,
                cols: 80,
                rlimits: vec![],
            };
            let session = ExecSession::spawn(
                id,
                &request("echo before; sleep 0.3; echo inherited; exit 23"),
                sender.with_incarnation(Some(old_owner)),
                None,
                crate::config::SecurityProfile::Default,
                None,
            )
            .unwrap();
            let pid = session.pid();
            state.sessions.insert(id, session);
            let before = time::timeout(Duration::from_secs(5), output.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(before.output, SessionOutput::Stdout(_)));
            let old_generation = sender.generation();

            restore_client_state(&mut state, &mut sender).await.unwrap();
            assert_eq!(
                unsafe { libc::kill(pid as i32, 0) },
                0,
                "restore killed the captured process"
            );
            assert_eq!(state.detached_sessions.len(), 1);
            assert!(state.sessions.is_empty());
            establish_relay_client(
                &mut state,
                RelayClientConnected {
                    id_start: id,
                    id_end_exclusive: end,
                    incarnation: new_owner,
                },
            )
            .unwrap();
            let fresh = ExecSession::spawn(
                id,
                &request("echo fresh; sleep 0.8; exit 24"),
                sender.with_incarnation(Some(new_owner)),
                None,
                crate::config::SecurityProfile::Default,
                None,
            )
            .unwrap();
            state.sessions.insert(id, fresh);
            let mut saw_old_exit = false;
            let mut saw_new_exit = false;
            let mut saw_inherited = false;
            time::timeout(Duration::from_secs(5), async {
                while !saw_old_exit || !saw_new_exit {
                    let envelope = output.recv().await.unwrap();
                    if envelope.generation == old_generation {
                        if let SessionOutput::Stdout(bytes) = &envelope.output {
                            saw_inherited |= String::from_utf8_lossy(bytes).contains("inherited");
                        }
                        if let SessionOutput::Exited(code) = &envelope.output {
                            assert_eq!(*code, 23);
                            saw_old_exit = true;
                        }
                        assert!(discard_inherited_output(
                            &mut state,
                            &envelope,
                            sender.generation()
                        ));
                        assert!(
                            state.sessions.contains_key(&id),
                            "old exit removed new session"
                        );
                    } else {
                        assert!(!discard_inherited_output(
                            &mut state,
                            &envelope,
                            sender.generation()
                        ));
                        if let SessionOutput::Exited(code) = envelope.output {
                            assert_eq!(code, 24);
                            saw_new_exit = true;
                        }
                    }
                }
            })
            .await
            .unwrap();
            assert!(saw_inherited, "inherited output reader stopped draining");
            assert!(
                state.detached_sessions.is_empty(),
                "exited inherited handles leaked"
            );
        }
    }

    #[tokio::test]
    async fn restore_closes_inherited_filesystem_handles_and_tcp_transfers() {
        use microsandbox_protocol::fs::{FsOp, FsOpenOptions, FsResponse, FsResponseData};
        use tokio::io::AsyncReadExt;

        async fn fs_request(
            state: &mut AgentState,
            sender: &SessionOutputSender,
            op: FsOp,
        ) -> FsResponse {
            let mut encoded = Vec::new();
            crate::fs::handle_fs_request(
                1,
                PROTOCOL_VERSION,
                FsRequest { op, bulk: None },
                &mut state.fs,
                &mut encoded,
                sender,
            )
            .await
            .unwrap();
            let mut bytes = BytesMut::from(encoded.as_slice());
            let Some(DecodedFrame::Control(reply)) =
                codec::try_decode_frame_from_bytes(&mut bytes).unwrap()
            else {
                panic!("missing filesystem response");
            };
            reply.payload::<FsResponse>().unwrap()
        }

        let mut state = AgentState::default();
        let (mut sender, _output) = SessionOutputSender::channel();
        let open = || FsOp::OpenFile {
            path: "/dev/null".into(),
            options: FsOpenOptions {
                read: true,
                ..Default::default()
            },
        };
        let Some(FsResponseData::Handle(old_handle)) =
            fs_request(&mut state, &sender, open()).await.data
        else {
            panic!("file did not open");
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        state.tcp_sessions.insert(
            2,
            TcpSession::open(
                2,
                TcpConnect {
                    host: "127.0.0.1".into(),
                    port: listener.local_addr().unwrap().port(),
                    bulk: None,
                },
                &sender,
            ),
        );
        let (mut peer, _) = time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();

        restore_client_state(&mut state, &mut sender).await.unwrap();
        assert!(state.tcp_sessions.is_empty());
        assert_eq!(
            time::timeout(Duration::from_secs(5), peer.read(&mut [0u8; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(
            !fs_request(&mut state, &sender, FsOp::FStat { handle: old_handle })
                .await
                .ok
        );
        let Some(FsResponseData::Handle(new_handle)) =
            fs_request(&mut state, &sender, open()).await.data
        else {
            panic!("fresh file did not open");
        };
        // Closing handles must not reset their allocator and alias a stale handle to a new file.
        assert_ne!(new_handle, old_handle);
        assert!(
            fs_request(&mut state, &sender, FsOp::FStat { handle: new_handle })
                .await
                .ok
        );
    }

    #[tokio::test]
    async fn restore_retires_unleased_output_and_can_repeat_with_the_same_ids() {
        let mut state = AgentState::default();
        let (mut sender, mut output) = SessionOutputSender::channel();
        for _ in 0..3 {
            let old = sender.clone();
            old.send(1, SessionOutput::Exited(7)).await;
            restore_client_state(&mut state, &mut sender).await.unwrap();
            let stale = output.recv().await.unwrap();
            assert!(discard_inherited_output(
                &mut state,
                &stale,
                sender.generation()
            ));
            // A late producer is as stale as an event that was already queued at the cut.
            old.send(1, SessionOutput::Exited(7)).await;
            assert!(discard_inherited_output(
                &mut state,
                &output.recv().await.unwrap(),
                sender.generation()
            ));
            sender.send(1, SessionOutput::Exited(8)).await;
            assert!(!discard_inherited_output(
                &mut state,
                &output.recv().await.unwrap(),
                sender.generation()
            ));
        }
    }

    #[tokio::test]
    async fn restore_bulk_cut_drops_queued_and_late_records_and_releases_capacity() {
        let (mut sender, _control, mut bulk, mut commands) = SessionOutputSender::split_channel();
        let old = sender.with_incarnation(Some([0x41; CLIENT_INCARNATION_SIZE]));
        let send = |sender: SessionOutputSender| async move {
            sender
                .send(
                    1,
                    SessionOutput::Bulk(crate::session::BulkSessionOutput::new(
                        BulkRecord {
                            id: 1,
                            kind: BulkKind::Filesystem,
                            flow: BulkFlow::GuestToHost,
                            offset: 0,
                            payload: bytes::Bytes::from_static(b"old"),
                        },
                        RawActivity::default(),
                    )),
                )
                .await
        };
        assert!(send(old.clone()).await);
        let reset = tokio::spawn(async move {
            sender.restore_generation().await.unwrap();
            sender
        });
        let command = commands.recv().await.unwrap();
        let mut generation = 0;
        let mut flows = HashMap::new();
        let mut active = VecDeque::new();
        let mut retired = HashMap::new();
        let mut retiring = HashSet::new();
        let cleanup = apply_bulk_output_command(
            command,
            &mut generation,
            &mut flows,
            &mut active,
            &mut retired,
            &mut retiring,
            &mut BulkOutputPosition::default(),
        )
        .unwrap();
        enqueue_bulk_output(
            bulk.recv().await.unwrap(),
            generation,
            &mut flows,
            &mut active,
            &retired,
            &retiring,
        )
        .unwrap();
        assert!(flows.is_empty());
        complete_bulk_output_cleanups(vec![cleanup], &mut retired, &mut retiring);
        let fresh = reset.await.unwrap();
        assert!(send(old).await);
        enqueue_bulk_output(
            bulk.recv().await.unwrap(),
            generation,
            &mut flows,
            &mut active,
            &retired,
            &retiring,
        )
        .unwrap();
        assert!(flows.is_empty());
        assert!(send(fresh.with_incarnation(Some([0x42; CLIENT_INCARNATION_SIZE]))).await);
        enqueue_bulk_output(
            bulk.recv().await.unwrap(),
            generation,
            &mut flows,
            &mut active,
            &retired,
            &retiring,
        )
        .unwrap();
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn restore_activity_backpressure_does_not_block_scheduler_control() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender.try_send(RawActivity::default()).unwrap();
        let mut pending = RawActivity {
            guest_messages: 3,
            fs_bytes: 17,
            ..Default::default()
        };
        publish_bulk_activity(&sender, &mut pending).unwrap();
        assert_eq!(pending.fs_bytes, 17);
        receiver.try_recv().unwrap();
        publish_bulk_activity(&sender, &mut pending).unwrap();
        assert_eq!(receiver.try_recv().unwrap().fs_bytes, 17);
        assert_eq!(pending.fs_bytes, 0);
    }
}
