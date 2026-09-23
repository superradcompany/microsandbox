//! Agent relay for the sandbox process.
//!
//! The [`AgentRelay`] reads from the console backend's ring buffers (data
//! written by agentd in the guest via virtio-console), listens on the local
//! platform IPC endpoint for SDK client connections, and transparently relays
//! protocol frames between clients and the guest agent.
//!
//! Each client is assigned a non-overlapping correlation ID range during
//! handshake so that the relay can route agent responses back to the correct
//! client without rewriting frame headers.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::IoSlice;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
#[cfg(unix)]
use microsandbox_agent_client::local_shm::{
    LocalBulkRelease, LocalShmError, LocalShmFrame, LocalShmServer, PreparedLocalBulk,
    SharedArenaProducer, decode_local_body, encode_local_bulk_ref, encode_local_bulk_release,
    send_local_shm_upgrade_fd,
};
#[cfg(unix)]
use microsandbox_filesystem::{BindIdentityMap, BindIdentityMapHandle};
use microsandbox_protocol::AGENT_RELAY_MAX_CLIENTS;
#[cfg(unix)]
use microsandbox_protocol::bulk::BulkRecord;
use microsandbox_protocol::bulk::{
    BULK_FLOW_MASK_GUEST_TO_HOST, BULK_HEADER_SIZE, BulkAccepted, BulkCancel, BulkCancelReason,
    BulkCredit, BulkFinish, BulkFlow, BulkKind, MAX_BULK_RECORD_PAYLOAD, MAX_BULK_WINDOW,
};
use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE, MAX_WIRE_FRAME};
#[cfg(test)]
use microsandbox_protocol::core::WORKLOAD_TRANSPORT_BARRIER_VERSION;
use microsandbox_protocol::core::{
    CoreError, InitAck, InitResolved, Ready, RelayClientDisconnected, WorkloadThaw, WorkloadThawed,
};
use microsandbox_protocol::exec::{ExecRequest, ExecSignal, ExecStderr, ExecStdout};
use microsandbox_protocol::fs::{FsRequest, FsResponse};
use microsandbox_protocol::message::{
    FLAG_BULK, FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL, FRAME_HEADER_SIZE, Message,
    MessageType,
};
use microsandbox_protocol::tcp::{TcpConnect, TcpFailed};
#[cfg(unix)]
use microsandbox_protocol::transport::LocalTransportReady;
use microsandbox_protocol::transport::{
    BULK_BINDING_SIZE, CLIENT_INCARNATION_SIZE, ClientIncarnation, RELAY_LEASE_FORMAT_V1,
    decode_bulk_hello, encode_bulk_ack, encode_relay_client_connected, relay_client_id_range,
    relay_client_slot, try_decode_incarnated_bulk_from_bytes,
    try_decode_relay_client_disconnected_ack_from_bytes,
};
use microsandbox_protocol::transport::{RelayClientConnected, RelayClientDisconnectedAck};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot, watch};

use self::input_stall::{INPUT_STALL_TIMEOUT, InputStall};
use super::workload_control::{WORKLOAD_CONTROL_ID, WorkloadControl};
use crate::checkpoint::RestoredAgentState;
use crate::clock::spawn_clock_sync_task;
use crate::console::ConsoleSharedState;
use crate::exec_log::{LogSource, LogWriter};
use crate::{RuntimeError, RuntimeResult};

#[path = "relay/envelope.rs"]
mod envelope;
#[path = "relay/input_stall.rs"]
mod input_stall;
#[cfg(test)]
#[path = "relay/input_stall_tests.rs"]
mod input_stall_tests;

#[cfg(test)]
#[path = "relay/namespace_tests.rs"]
mod namespace_tests;

//--------------------------------------------------------------------------------------------------
// Types: capture
//--------------------------------------------------------------------------------------------------

/// Metadata recorded for each observed exec session. Populated by
/// `client_reader_task` when an `ExecRequest` arrives, consumed by
/// the ring reader's tap, and removed on `ExecExited`.
#[derive(Debug, Clone, Copy)]
struct SessionInfo {
    /// Monotonic per-relay session id. Distinct from the protocol
    /// correlation id, which can be reused across slot recycling
    /// (each `msb exec` is a separate client; slot 0 is freed and
    /// reassigned, so the same correlation id can appear twice
    /// within a sandbox lifetime). The monotonic counter gives every
    /// session a unique id within the relay's lifetime, which is
    /// what users see in `exec.log` entries.
    session_id: u64,

    /// Whether the session was opened in pty mode (drives
    /// `LogSource::Output` vs `Stdout` tagging).
    is_pty: bool,
}

/// Per-session bookkeeping for the log tap. Keyed by protocol
/// correlation id (which is what subsequent `Exec*` frames carry).
type SessionRegistry = std::sync::Mutex<HashMap<u32, SessionInfo>>;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Size of the length prefix in the wire format.
const LEN_PREFIX_SIZE: usize = 4;
const RESTORE_ACTIVATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const RESTORE_CONTROL_ID: u32 = u32::MAX;

/// Aggregate guest-to-client bytes retained by the relay.
const CLIENT_OUTPUT_BYTE_CAPACITY: usize = 32 * 1024 * 1024;

/// Maximum time a local SDK socket may make no progress on an admitted output batch.
const CLIENT_OUTPUT_STALL_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Separate dual-port reserve for latency-sensitive guest control frames.
const CONTROL_LANE_OUTPUT_BYTE_CAPACITY: usize =
    2 * MAX_WIRE_FRAME.div_ceil(OUTPUT_BUDGET_GRANULE) * OUTPUT_BUDGET_GRANULE;

/// Maximum guest output retained for one SDK client across both physical lanes.
///
/// Matching the sum of the lane budgets guarantees that scheduling a healthy writer cannot itself
/// exhaust this bound. Actual stalls are detected by elapsed socket-write progress instead of a
/// transient queue depth.
const CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY: usize =
    CLIENT_OUTPUT_BYTE_CAPACITY + CONTROL_LANE_OUTPUT_BYTE_CAPACITY;

/// Allocation granularity used for relay output admission.
const OUTPUT_BUDGET_GRANULE: usize = 4096;

/// Maximum bytes opportunistically coalesced in one client socket batch.
const CLIENT_WRITE_BATCH_BYTES: usize = 256 * 1024;

/// Maximum frame slices opportunistically coalesced in one client socket batch.
const CLIENT_WRITE_BATCH_FRAMES: usize = 64;

/// Separate admission reserves share one FIFO. Permits survive dequeue and physical writes, so
/// credit-starved payload cannot consume the space needed by another client's metadata.
const AGENT_WRITE_CLASS_FRAMES: usize = 8;
const AGENT_WRITE_CHANNEL_CAPACITY: usize = 2 * AGENT_WRITE_CLASS_FRAMES;
const AGENT_WRITE_DATA_BYTES: usize = 32 * 1024 * 1024;
const AGENT_WRITE_CONTROL_BYTES: usize = 8 * 1024 * 1024;

/// Aggregate client-to-bulk-lane bytes waiting outside the console backend.
const BULK_WRITE_BYTE_CAPACITY: usize = 32 * 1024 * 1024;

/// Maximum bytes queued for one bulk correlation.
const BULK_WRITE_FLOW_CAPACITY: usize = 8 * 1024 * 1024;

/// Per-correlation deficit increment for the bulk lane.
const BULK_WRITE_QUANTUM: usize = 256 * 1024;

/// Maximum bytes one correlation may write in one bulk scheduling round.
const BULK_WRITE_MAX_BURST: usize = MAX_BULK_RECORD_PAYLOAD as usize;

/// Maximum concurrently queued flows from one relay client.
const BULK_WRITE_MAX_FLOWS_PER_CLIENT: usize = 64;

/// Maximum out-of-order records retained for one guest-to-host bulk flow.
const BULK_MERGE_MAX_PENDING_RECORDS: usize = 1024;

/// Bounded window for publishing typed cancellation during a relay transport failure.
const RELAY_FAILURE_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// State for a connected client.
struct ClientState {
    /// Transport identity for this leased ownership of the slot, independent of lane topology.
    incarnation: Option<ClientIncarnation>,

    /// Active session IDs owned by this client (tracked for disconnect cleanup).
    active_sessions: HashSet<u32>,

    /// Active generation-8 bulk operations that need typed transport-failure cancellation.
    active_bulk: Arc<std::sync::Mutex<HashMap<u32, BulkKind>>>,
    /// Channel for sending frames to this client's writer task.
    /// Using a channel avoids holding the client mutex across async writes.
    /// Uses `Bytes` for zero-copy frame forwarding from the ring buffer.
    write_tx: mpsc::UnboundedSender<ClientWrite>,

    /// Byte admission for this client's nonblocking writer mailbox.
    write_budget: Arc<Semaphore>,

    /// Requests teardown when this client's bounded output path stops making progress.
    disconnect_tx: watch::Sender<bool>,

    /// Runtime-to-SDK arena producer after this client accepts local-shm-v1.
    #[cfg(unix)]
    local_outbound: Option<SharedArenaProducer>,
}

/// One primary-lane write, optionally acknowledged after physical ring admission.
pub(crate) struct ControlWrite {
    data: Bytes,
    completion: Option<oneshot::Sender<()>>,
    uses_data_credit: bool,
    order: ControlOrder,
    admission: Option<ControlAdmission>,
}

/// A client lease transition fences its range; shutdown and unattributed internal traffic fence
/// the whole FIFO. Ordinary correlations may bypass only unrelated blocked payload.
#[derive(Clone, Copy)]
enum ControlOrder {
    Correlation(u32),
    MaintenanceClock,
    TcpInputData(u32),
    TcpInputFinish(u32),
    TcpOutputCredit(u32),
    ClientFence { start: u32, end: u32 },
    GlobalFence,
}

struct ControlAdmission {
    _bytes: tokio::sync::OwnedSemaphorePermit,
    _frame: tokio::sync::OwnedSemaphorePermit,
}

/// Bounded, class-reserved admission into the existing ordinary transport queue. No payload is
/// copied, and cancellation releases reservations without dropping any already accepted frame.
#[derive(Clone)]
pub(crate) struct ControlWriter {
    tx: mpsc::Sender<ControlWrite>,
    data_bytes: Arc<Semaphore>,
    data_frames: Arc<Semaphore>,
    control_bytes: Arc<Semaphore>,
    control_frames: Arc<Semaphore>,
}

/// Terminal outcome and the transport paths still available for failure cleanup.
struct RelayExit {
    failure: Option<RuntimeError>,
    control_writer_usable: bool,
    can_observe_failure_terminals: bool,
}

/// Every exit, including task abortion while waiting for ring capacity, wakes lifecycle waiters.
struct WorkloadWriterGuard(Arc<WorkloadControl>);

/// A disconnected leased owner whose untagged control output is still being drained.
struct PendingClientDisconnect {
    id_start: u32,
    id_end_exclusive: u32,
    completion: oneshot::Sender<()>,
}

/// Commands that serialize operation lifecycle changes with guest-lane merge events.
enum MergeCommand {
    Register {
        incarnation: ClientIncarnation,
        id: u32,
        completion: oneshot::Sender<RuntimeResult<()>>,
    },
    DropFlow {
        incarnation: ClientIncarnation,
        id: u32,
        completion: oneshot::Sender<()>,
    },
    DropIncarnation {
        incarnation: ClientIncarnation,
        completion: oneshot::Sender<()>,
    },
}

/// Shared routing and observability state owned by the guest-to-host reader.
#[derive(Default)]
struct RestoreInput {
    control: BytesMut,
    bulk: BytesMut,
}

struct RingReaderContext {
    initial: RestoreInput,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    log_writer: Option<Arc<LogWriter>>,
    session_registry: Arc<SessionRegistry>,
    pending_disconnects: Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
    bulk_writer: Option<mpsc::Sender<BulkWriterCommand>>,
}

/// A client-bound frame whose aggregate capacity lives until the socket accepts it.
struct ClientWrite {
    data: ClientWriteData,
    /// Aggregate physical-lane admission, retained until the SDK socket consumes a guest frame.
    /// Runtime-generated terminal rejections have no guest-lane allocation and therefore carry
    /// no permit here.
    _lane_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// Per-client admission, retained for the same lifetime as the aggregate permit.
    _client_permit: tokio::sync::OwnedSemaphorePermit,
}

/// One item in the canonical guest-to-SDK output order.
///
/// Shared-arena descriptors deliberately live in the same mailbox as in-band frames. Keeping
/// them on a separate priority channel can let a later bulk descriptor overtake an earlier
/// terminal control frame (or vice versa), which truncates otherwise valid full-duplex streams.
enum ClientWriteData {
    Inline(Bytes),
    #[cfg(unix)]
    LocalBulk(PreparedLocalBulk),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BulkOpenAdmission {
    Accepted,
    Duplicate,
    LimitReached,
}

impl ClientWriteData {
    fn inline(&self) -> Option<&Bytes> {
        match self {
            Self::Inline(data) => Some(data),
            #[cfg(unix)]
            Self::LocalBulk(_) => None,
        }
    }

    fn inline_mut(&mut self) -> Option<&mut Bytes> {
        match self {
            Self::Inline(data) => Some(data),
            #[cfg(unix)]
            Self::LocalBulk(_) => None,
        }
    }
}

/// Nonblocking handles cloned from one live client owner before guest-output routing.
struct ClientRoute {
    write_tx: mpsc::UnboundedSender<ClientWrite>,
    write_budget: Arc<Semaphore>,
    disconnect_tx: watch::Sender<bool>,
    #[cfg(unix)]
    local_outbound: Option<SharedArenaProducer>,
}

/// Small priority writes that never carry bulk payload bytes through `agent.sock`.
#[cfg(unix)]
enum LocalClientWrite {
    Upgrade {
        server: Arc<LocalShmServer>,
        completion: oneshot::Sender<Result<(), String>>,
    },
    Release(LocalBulkRelease),
}

/// Client-originated raw frame retained until the bulk console ring accepts it.
struct BulkWrite {
    id: u32,
    incarnation: ClientIncarnation,
    data: BulkWriteData,
    /// Validated direction carried from the client boundary.
    flow: BulkFlow,
    /// Validated payload length carried through scheduling to avoid reparsing the wire header.
    payload_len: usize,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// One in-band frame or shared payload split into its unchanged wire header and body.
enum BulkWriteData {
    Inline(Bytes),
    #[cfg(unix)]
    Shared {
        header: Bytes,
        payload: Bytes,
    },
}

/// Commands processed in-order by the host-to-guest bulk scheduler.
enum BulkWriterCommand {
    Write(BulkWrite),
    DropFlow {
        incarnation: ClientIncarnation,
        id: u32,
        completion: oneshot::Sender<()>,
    },
    DropIncarnation {
        incarnation: ClientIncarnation,
        completion: oneshot::Sender<()>,
    },
}

/// One host-to-guest correlation in the bulk DRR scheduler.
struct BulkWriteFlow {
    queue: VecDeque<BulkWrite>,
    queued_bytes: usize,
    deficit: usize,
}

/// Physical lane on which a guest-originated frame arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestLane {
    Control,
    Bulk,
}

/// Parsed frame whose admission permit follows it through cross-lane reordering.
struct LaneFrame {
    frame: RawFrame,
    /// Range owner carried by or inferred for this internal dual-port event.
    incarnation: Option<ClientIncarnation>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Ordered events extracted from the physical guest-to-host lanes.
enum LaneEvent {
    Frame(LaneFrame),
    DisconnectAck(RelayClientDisconnectedAck),
}

/// Guest-to-host ordering state for one generation-8 bulk correlation.
#[derive(Default)]
struct GuestMergeFlow {
    cancelling: bool,
    accepted_forwarded: bool,
    guest_to_host: bool,
    next_raw_offset: u64,
    pending_raw: BTreeMap<u64, LaneFrame>,
    pending_raw_bytes: usize,
    pending_finish: Option<(u64, LaneFrame)>,
    finish_forwarded: bool,
    pending_terminal: Option<LaneFrame>,
}

/// Cross-lane merger that reconstructs one valid outward SDK stream.
#[derive(Default)]
struct GuestFrameMerger {
    flows: HashMap<(ClientIncarnation, u32), GuestMergeFlow>,
    /// Compact owner-local bitmaps remember retired IDs without one allocation per operation.
    retired: HashMap<ClientIncarnation, Vec<u64>>,
}

/// The agent relay running in the sandbox process.
///
/// Reads agent frames from the console backend's ring buffers and listens
/// for client connections on a Unix domain socket. Frames are routed between
/// clients and the guest agent without decoding.
pub struct AgentRelay {
    restored_input: RestoreInput,
    /// Shared ring buffers + wake pipes for console backend communication.
    shared: Arc<ConsoleSharedState>,
    /// Optional second ring pair dedicated to generation-8 raw records.
    bulk_shared: Option<Arc<ConsoleSharedState>>,
    /// Identity observed and acknowledged on the second physical port.
    bulk_connection_id: Option<[u8; 16]>,
    /// Whether `core.ready` selected the bound dual-port profile.
    dual_port_active: bool,
    /// Whether the relay selected acknowledged correlation-range ownership.
    range_lease_active: bool,
    /// Local IPC listener for client connections.
    listener: Option<AgentListener>,
    /// Local IPC endpoint address.
    endpoint: PathBuf,
    /// Cached `core.ready` frame bytes (length-prefixed wire format).
    ready_frame: Option<Vec<u8>>,
    kernel_clock_synchronized: bool,
    /// Optional `exec.log` writer. When set, the ring reader task
    /// captures the primary session's stdout/stderr to JSON Lines.
    log_writer: Option<Arc<LogWriter>>,
    /// Shared user-volume bind identity map to install before `core.ready`.
    #[cfg(unix)]
    bind_identity_map: Option<BindIdentityMapHandle>,
    /// Number of user-volume mounts that use the shared bind identity map.
    #[cfg(unix)]
    bind_identity_map_mount_count: usize,
}

/// Platform-specific listener for SDK client connections.
struct AgentListener {
    #[cfg(unix)]
    inner: UnixListener,
    #[cfg(windows)]
    pipe_name: PathBuf,
    #[cfg(windows)]
    first_pipe_instance: bool,
}

#[cfg(unix)]
type AgentConnection = tokio::net::UnixStream;

#[cfg(windows)]
type AgentConnection = NamedPipeServer;

/// A frame extracted from the byte stream, kept as raw bytes for transparent
/// forwarding.
struct RawFrame {
    /// The complete frame bytes including the 4-byte length prefix.
    /// Uses `Bytes` for zero-copy extraction from the ring buffer.
    data: Bytes,
    /// The correlation ID extracted from the frame header.
    id: u32,
    /// The flags byte extracted from the frame header.
    flags: u8,
}

#[derive(serde::Serialize)]
struct RestoreActivationRecord<'a> {
    attempt_id: &'a str,
    vm_generation_id: String,
    state: &'a str,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlWrite {
    pub(crate) fn clock_sync() -> RuntimeResult<Self> {
        // Reserve the largest CBOR integer representation. The scheduler replaces this sentinel
        // before charging transport bytes, so queued time is never replayed after a long pause.
        Ok(Self {
            order: ControlOrder::MaintenanceClock,
            ..crate::clock::encode_clock_sync_frame(u64::MAX)?.into()
        })
    }

    fn ordinary(data: Bytes, id: u32, uses_data_credit: bool) -> Self {
        let order = if id == 0
            || data
                .get(LEN_PREFIX_SIZE + 4)
                .is_some_and(|flags| flags & FLAG_SHUTDOWN != 0)
        {
            ControlOrder::GlobalFence
        } else {
            ControlOrder::Correlation(id)
        };
        Self {
            data,
            completion: None,
            uses_data_credit,
            order,
            admission: None,
        }
    }

    fn client_fence(data: Bytes, start: u32, end: u32) -> Self {
        Self {
            order: ControlOrder::ClientFence { start, end },
            ..data.into()
        }
    }

    /// Only the independent TCP return-credit flow may cross ordered input. Raw metadata was
    /// already validated by the client reader; parse only the two small control payloads here.
    fn classify_tcp_order(
        &mut self,
        id: u32,
        raw: Option<(BulkKind, BulkFlow, u64, usize)>,
        message: Option<&Message>,
    ) {
        if matches!(self.order, ControlOrder::GlobalFence) {
            return;
        }
        if matches!(raw, Some((BulkKind::Tcp, BulkFlow::HostToGuest, _, _))) {
            self.order = ControlOrder::TcpInputData(id);
            return;
        }
        let Some(message) = message else {
            return;
        };
        match message.t {
            MessageType::BulkFinish
                if message.payload::<BulkFinish>().is_ok_and(|finish| {
                    finish.kind == BulkKind::Tcp && finish.flow == BulkFlow::HostToGuest
                }) =>
            {
                self.order = ControlOrder::TcpInputFinish(id);
            }
            MessageType::BulkCredit
                if message.payload::<BulkCredit>().is_ok_and(|credit| {
                    credit.kind == BulkKind::Tcp
                        && credit.flow == BulkFlow::GuestToHost
                        && credit.credit_limit >= credit.consumed_offset
                        && credit.credit_limit - credit.consumed_offset <= MAX_BULK_WINDOW
                }) =>
            {
                self.order = ControlOrder::TcpOutputCredit(id);
            }
            _ => {}
        }
    }
}

impl ControlOrder {
    fn conflicts(self, other: Self) -> bool {
        match (self, other) {
            (Self::GlobalFence, _) | (_, Self::GlobalFence) => true,
            (Self::MaintenanceClock, Self::MaintenanceClock) => true,
            (Self::MaintenanceClock, _) | (_, Self::MaintenanceClock) => false,
            (Self::ClientFence { start: a, end: b }, Self::ClientFence { start: c, end: d }) => {
                a < d && c < b
            }
            (Self::ClientFence { start, end }, correlation)
            | (correlation, Self::ClientFence { start, end }) => {
                (start..end).contains(&correlation.id())
            }
            // Credit advances the opposite (guest-to-host) producer, not these input bytes or
            // their end marker. Reordering only the credit breaks a full-duplex credit cycle;
            // input data and input finish still conflict with each other in their original FIFO.
            (Self::TcpInputData(_) | Self::TcpInputFinish(_), Self::TcpOutputCredit(_)) => false,
            (a, b) => a.id() == b.id(),
        }
    }

    fn id(self) -> u32 {
        match self {
            Self::Correlation(id)
            | Self::TcpInputData(id)
            | Self::TcpInputFinish(id)
            | Self::TcpOutputCredit(id) => id,
            Self::ClientFence { .. } | Self::GlobalFence | Self::MaintenanceClock => {
                unreachable!("fence or maintenance order handled first")
            }
        }
    }
}

impl ControlWriter {
    fn new() -> (Self, mpsc::Receiver<ControlWrite>) {
        let (tx, rx) = mpsc::channel(AGENT_WRITE_CHANNEL_CAPACITY);
        (Self::from_sender(tx), rx)
    }

    fn from_sender(tx: mpsc::Sender<ControlWrite>) -> Self {
        Self {
            tx,
            data_bytes: Arc::new(Semaphore::new(AGENT_WRITE_DATA_BYTES)),
            data_frames: Arc::new(Semaphore::new(AGENT_WRITE_CLASS_FRAMES)),
            control_bytes: Arc::new(Semaphore::new(AGENT_WRITE_CONTROL_BYTES)),
            control_frames: Arc::new(Semaphore::new(AGENT_WRITE_CLASS_FRAMES)),
        }
    }

    fn budgets(&self, write: &ControlWrite) -> (&Arc<Semaphore>, &Arc<Semaphore>) {
        if write.uses_data_credit {
            (&self.data_bytes, &self.data_frames)
        } else {
            (&self.control_bytes, &self.control_frames)
        }
    }

    pub(crate) async fn send(
        &self,
        mut write: ControlWrite,
    ) -> Result<(), mpsc::error::SendError<ControlWrite>> {
        let Ok(bytes) = u32::try_from(write.data.len()) else {
            return Err(mpsc::error::SendError(write));
        };
        let (byte_budget, frame_budget) = self.budgets(&write);
        // Closing the receiver must also wake senders waiting for a class reservation. A canceled
        // send drops its partial permits; frames already in the canonical queue retain theirs.
        let reservation = async {
            let frame = Arc::clone(frame_budget).acquire_owned().await.ok()?;
            let bytes = Arc::clone(byte_budget)
                .acquire_many_owned(bytes)
                .await
                .ok()?;
            Some(ControlAdmission {
                _bytes: bytes,
                _frame: frame,
            })
        };
        let admission = tokio::select! {
            biased;
            _ = self.tx.closed() => None,
            admission = reservation => admission,
        };
        let Some(admission) = admission else {
            return Err(mpsc::error::SendError(write));
        };
        write.admission = Some(admission);
        self.tx.send(write).await.map_err(|mut error| {
            error.0.admission.take();
            error
        })
    }

    fn try_send(
        &self,
        mut write: ControlWrite,
    ) -> Result<(), mpsc::error::TrySendError<ControlWrite>> {
        if self.tx.is_closed() {
            return Err(mpsc::error::TrySendError::Closed(write));
        }
        let Ok(bytes) = u32::try_from(write.data.len()) else {
            return Err(mpsc::error::TrySendError::Full(write));
        };
        let (byte_budget, frame_budget) = self.budgets(&write);
        let Ok(frame) = Arc::clone(frame_budget).try_acquire_owned() else {
            return Err(mpsc::error::TrySendError::Full(write));
        };
        let Ok(bytes) = Arc::clone(byte_budget).try_acquire_many_owned(bytes) else {
            return Err(mpsc::error::TrySendError::Full(write));
        };
        write.admission = Some(ControlAdmission {
            _bytes: bytes,
            _frame: frame,
        });
        self.tx.try_send(write).map_err(|error| match error {
            mpsc::error::TrySendError::Full(mut write) => {
                write.admission.take();
                mpsc::error::TrySendError::Full(write)
            }
            mpsc::error::TrySendError::Closed(mut write) => {
                write.admission.take();
                mpsc::error::TrySendError::Closed(write)
            }
        })
    }
}

impl GuestFrameMerger {
    /// Register an opening operation before its request can reach agentd.
    fn register(&mut self, incarnation: ClientIncarnation, id: u32) -> RuntimeResult<()> {
        if self.is_retired(incarnation, id) || self.flows.contains_key(&(incarnation, id)) {
            return Err(RuntimeError::Custom(format!(
                "correlation {id} was reused within one client incarnation"
            )));
        }
        self.flows
            .insert((incarnation, id), GuestMergeFlow::default());
        Ok(())
    }

    /// Mark one operation cancelling and release all held data records.
    fn drop_flow(&mut self, incarnation: ClientIncarnation, id: u32) {
        if let Some(flow) = self.flows.get_mut(&(incarnation, id)) {
            flow.cancelling = true;
            flow.pending_raw.clear();
            flow.pending_raw_bytes = 0;
            flow.pending_finish = None;
            // A previously held success terminal cannot survive discarding the bytes it covered.
            // The peer now owes a fresh ordinary terminal failure for the cancellation.
            flow.pending_terminal = None;
        }
    }

    /// Drop all held frames owned by one disconnected client incarnation.
    fn drop_incarnation(&mut self, incarnation: ClientIncarnation) {
        self.flows.retain(|(owner, _), _| *owner != incarnation);
        self.retired.remove(&incarnation);
    }

    fn is_retired(&self, incarnation: ClientIncarnation, id: u32) -> bool {
        relay_correlation_is_retired(&self.retired, incarnation, id)
    }

    fn retire(&mut self, incarnation: ClientIncarnation, id: u32) -> RuntimeResult<()> {
        retire_relay_correlation(&mut self.retired, incarnation, id)
    }

    /// Admit one lane event and return the outward frames whose dependencies are satisfied.
    fn push(&mut self, lane_frame: LaneFrame) -> RuntimeResult<Vec<LaneFrame>> {
        let incarnation = lane_frame.incarnation.ok_or_else(|| {
            RuntimeError::Custom("dual-port merge event is missing client incarnation".into())
        })?;
        if lane_frame.frame.flags == FLAG_BULK {
            return self.push_raw(lane_frame);
        }

        let message = decode_frame(lane_frame.frame.data.as_ref())?;
        let key = (incarnation, message.id);
        match message.t {
            MessageType::BulkAccepted => {
                let accepted: BulkAccepted = message.payload().map_err(|error| {
                    RuntimeError::Custom(format!("decode bulk acceptance: {error}"))
                })?;
                let Some(flow) = self.flows.get_mut(&key) else {
                    if self.is_retired(incarnation, message.id) {
                        return Ok(Vec::new());
                    }
                    return Err(RuntimeError::Custom(format!(
                        "bulk acceptance for unregistered correlation {}",
                        message.id
                    )));
                };
                if flow.accepted_forwarded {
                    return Err(RuntimeError::Custom(format!(
                        "duplicate bulk acceptance for correlation {}",
                        message.id
                    )));
                }
                flow.accepted_forwarded = true;
                flow.guest_to_host = accepted.flows & BULK_FLOW_MASK_GUEST_TO_HOST != 0;
                if !flow.guest_to_host && !flow.pending_raw.is_empty() {
                    return Err(RuntimeError::Custom(format!(
                        "guest sent raw records for disabled flow {}",
                        message.id
                    )));
                }

                let mut ready = vec![lane_frame];
                self.drain_flow(key, &mut ready)?;
                Ok(ready)
            }
            MessageType::BulkFinish => {
                let finish: BulkFinish = message.payload().map_err(|error| {
                    RuntimeError::Custom(format!("decode bulk finish: {error}"))
                })?;
                if finish.flow != BulkFlow::GuestToHost {
                    return Ok(vec![lane_frame]);
                }
                let flow = self.flows.get_mut(&key).ok_or_else(|| {
                    RuntimeError::Custom(format!(
                        "bulk finish arrived before acceptance for correlation {}",
                        message.id
                    ))
                })?;
                if !flow.accepted_forwarded || !flow.guest_to_host {
                    return Err(RuntimeError::Custom(format!(
                        "bulk finish arrived for inactive guest-to-host flow {}",
                        message.id
                    )));
                }
                if finish.final_offset < flow.next_raw_offset {
                    return Err(RuntimeError::Custom(format!(
                        "bulk finish {} regressed behind forwarded offset {}",
                        finish.final_offset, flow.next_raw_offset
                    )));
                }
                if flow.pending_finish.is_some() {
                    return Err(RuntimeError::Custom(format!(
                        "duplicate bulk finish for correlation {}",
                        message.id
                    )));
                }
                flow.pending_finish = Some((finish.final_offset, lane_frame));
                let mut ready = Vec::new();
                self.drain_flow(key, &mut ready)?;
                Ok(ready)
            }
            MessageType::BulkCancel => {
                let Some(flow) = self.flows.get_mut(&key) else {
                    return if self.is_retired(incarnation, message.id) {
                        Ok(Vec::new())
                    } else {
                        Err(RuntimeError::Custom(format!(
                            "bulk cancellation for unregistered correlation {}",
                            message.id
                        )))
                    };
                };
                flow.cancelling = true;
                flow.pending_raw.clear();
                flow.pending_raw_bytes = 0;
                flow.pending_finish = None;
                Ok(vec![lane_frame])
            }
            _ if lane_frame.frame.flags & FLAG_TERMINAL != 0 => {
                let Some(flow) = self.flows.get_mut(&key) else {
                    return if self.is_retired(incarnation, message.id) {
                        Ok(Vec::new())
                    } else {
                        Ok(vec![lane_frame])
                    };
                };
                if flow.cancelling {
                    self.flows.remove(&key);
                    self.retire(incarnation, message.id)?;
                    return Ok(vec![lane_frame]);
                }
                if !flow.guest_to_host || flow.finish_forwarded {
                    self.flows.remove(&key);
                    self.retire(incarnation, message.id)?;
                    return Ok(vec![lane_frame]);
                }
                if flow.pending_terminal.replace(lane_frame).is_some() {
                    return Err(RuntimeError::Custom(format!(
                        "duplicate terminal frame for bulk correlation {}",
                        message.id
                    )));
                }
                Ok(Vec::new())
            }
            _ => Ok(vec![lane_frame]),
        }
    }

    fn push_raw(&mut self, lane_frame: LaneFrame) -> RuntimeResult<Vec<LaneFrame>> {
        let incarnation = lane_frame.incarnation.ok_or_else(|| {
            RuntimeError::Custom("dedicated bulk record is missing client incarnation".into())
        })?;
        let (offset, end, flow_direction) = raw_bulk_offsets(&lane_frame.frame)?;
        if flow_direction != BulkFlow::GuestToHost {
            return Err(RuntimeError::Custom(format!(
                "guest sent host-to-guest raw record for correlation {}",
                lane_frame.frame.id
            )));
        }
        let id = lane_frame.frame.id;
        let key = (incarnation, id);
        let Some(flow) = self.flows.get_mut(&key) else {
            if self.is_retired(incarnation, id) {
                return Ok(Vec::new());
            }
            return Err(RuntimeError::Custom(format!(
                "raw record for unregistered correlation {id}"
            )));
        };
        if flow.cancelling {
            return Ok(Vec::new());
        }
        if flow.finish_forwarded {
            return Err(RuntimeError::Custom(format!(
                "raw record arrived after bulk finish for correlation {id}"
            )));
        }
        if flow
            .pending_finish
            .as_ref()
            .is_some_and(|(final_offset, _)| end > *final_offset)
        {
            return Err(RuntimeError::Custom(format!(
                "raw record end {end} exceeds pending finish for correlation {id}"
            )));
        }
        if offset < flow.next_raw_offset || flow.pending_raw.contains_key(&offset) {
            return Err(RuntimeError::Custom(format!(
                "duplicate or regressed raw offset {offset} for correlation {id}"
            )));
        }
        if let Some((_, predecessor)) = flow.pending_raw.range(..offset).next_back() {
            let (_, predecessor_end, _) = raw_bulk_offsets(&predecessor.frame)?;
            if predecessor_end > offset {
                return Err(RuntimeError::Custom(format!(
                    "overlapping raw record at offset {offset} for correlation {id}"
                )));
            }
        }
        if let Some((successor_offset, _)) = flow.pending_raw.range(offset..).next()
            && end > *successor_offset
        {
            return Err(RuntimeError::Custom(format!(
                "overlapping raw record ending at {end} for correlation {id}"
            )));
        }
        if flow.accepted_forwarded
            && flow.guest_to_host
            && offset == flow.next_raw_offset
            && flow.pending_raw.is_empty()
        {
            // The normal case is already ordered. Forward it without a BTreeMap insertion/removal
            // and let `drain_flow` release any finish or terminal that this record satisfied.
            flow.next_raw_offset = end;
            let mut ready = vec![lane_frame];
            self.drain_flow(key, &mut ready)?;
            return Ok(ready);
        }
        if flow.pending_raw.len() >= BULK_MERGE_MAX_PENDING_RECORDS {
            return Err(RuntimeError::Custom(format!(
                "guest bulk flow {id} exceeded merge record budget"
            )));
        }
        let payload_len = usize::try_from(end - offset)
            .map_err(|_| RuntimeError::Custom("bulk payload length overflow".into()))?;
        let pending_raw_bytes = flow
            .pending_raw_bytes
            .checked_add(payload_len)
            .ok_or_else(|| RuntimeError::Custom("bulk merge byte budget overflow".into()))?;
        if pending_raw_bytes > BULK_WRITE_FLOW_CAPACITY {
            return Err(RuntimeError::Custom(format!(
                "guest bulk flow {id} exceeded merge byte budget"
            )));
        }
        flow.pending_raw_bytes = pending_raw_bytes;
        flow.pending_raw.insert(offset, lane_frame);

        let mut ready = Vec::new();
        self.drain_flow(key, &mut ready)?;
        Ok(ready)
    }

    fn drain_flow(
        &mut self,
        key: (ClientIncarnation, u32),
        ready: &mut Vec<LaneFrame>,
    ) -> RuntimeResult<()> {
        let id = key.1;
        let Some(flow) = self.flows.get_mut(&key) else {
            return Ok(());
        };
        if flow.cancelling || !flow.accepted_forwarded || !flow.guest_to_host {
            return Ok(());
        }

        while let Some(frame) = flow.pending_raw.remove(&flow.next_raw_offset) {
            let (offset, end, _) = raw_bulk_offsets(&frame.frame)?;
            flow.pending_raw_bytes = flow
                .pending_raw_bytes
                .saturating_sub(usize::try_from(end - offset).unwrap_or(usize::MAX));
            flow.next_raw_offset = end;
            ready.push(frame);
        }

        let finish_ready = flow
            .pending_finish
            .as_ref()
            .is_some_and(|(final_offset, _)| *final_offset == flow.next_raw_offset);
        if finish_ready && !flow.pending_raw.is_empty() {
            return Err(RuntimeError::Custom(format!(
                "bulk records exceed final offset for correlation {id}"
            )));
        }
        let mut terminal_forwarded = false;
        if finish_ready {
            let (_, finish) = flow.pending_finish.take().expect("checked finish exists");
            flow.finish_forwarded = true;
            ready.push(finish);
            if let Some(terminal) = flow.pending_terminal.take() {
                ready.push(terminal);
                terminal_forwarded = true;
            }
        }
        if terminal_forwarded {
            self.flows.remove(&key);
            self.retire(key.0, key.1)?;
        }
        Ok(())
    }
}

impl AgentListener {
    fn bind(endpoint: &Path) -> RuntimeResult<Self> {
        #[cfg(unix)]
        {
            // Remove stale socket file if it exists.
            if endpoint.exists() {
                let _ = std::fs::remove_file(endpoint);
            }

            // Ensure the parent directory exists.
            if let Some(parent) = endpoint.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let inner = UnixListener::bind(endpoint)?;
            Ok(Self { inner })
        }

        #[cfg(windows)]
        {
            Ok(Self {
                pipe_name: endpoint.to_path_buf(),
                first_pipe_instance: true,
            })
        }
    }

    async fn accept(&mut self) -> std::io::Result<AgentConnection> {
        #[cfg(unix)]
        {
            let (stream, _addr) = self.inner.accept().await?;
            Ok(stream)
        }

        #[cfg(windows)]
        {
            let mut options = ServerOptions::new();
            options.pipe_mode(PipeMode::Byte);
            let first_pipe_instance = self.first_pipe_instance;
            if first_pipe_instance {
                options.first_pipe_instance(true);
            }

            let server = options.create(&self.pipe_name)?;
            if first_pipe_instance {
                self.first_pipe_instance = false;
            }
            server.connect().await?;
            Ok(server)
        }
    }

    fn cleanup(&self, endpoint: &Path) {
        #[cfg(unix)]
        {
            // The control endpoint is derived from the relay endpoint and is
            // owned by the same runtime lifetime.
            let _ = crate::ipc::remove_socket_pair(endpoint);
        }

        #[cfg(windows)]
        {
            let _ = endpoint;
        }
    }
}

impl AgentRelay {
    /// Create a new agent relay.
    ///
    /// Takes the shared console state (ring buffers) and the local IPC endpoint
    /// where client connections will be accepted.
    pub async fn new(
        agent_sock_path: &Path,
        shared: Arc<ConsoleSharedState>,
    ) -> RuntimeResult<Self> {
        Self::new_with_bulk(agent_sock_path, shared, None).await
    }

    /// Create a relay with an optional unpublished bulk console lane.
    pub async fn new_with_bulk(
        agent_sock_path: &Path,
        shared: Arc<ConsoleSharedState>,
        bulk_shared: Option<Arc<ConsoleSharedState>>,
    ) -> RuntimeResult<Self> {
        let listener = AgentListener::bind(agent_sock_path)?;
        tracing::info!("agent relay listening on {}", agent_sock_path.display());

        Ok(Self {
            shared,
            bulk_shared,
            restored_input: RestoreInput::default(),
            bulk_connection_id: None,
            dual_port_active: false,
            range_lease_active: false,
            listener: Some(listener),
            endpoint: agent_sock_path.to_path_buf(),
            ready_frame: None,
            kernel_clock_synchronized: false,
            log_writer: None,
            #[cfg(unix)]
            bind_identity_map: None,
            #[cfg(unix)]
            bind_identity_map_mount_count: 0,
        })
    }

    /// Construct a relay without publishing its client endpoint.
    ///
    /// Checkpoint restore uses the console rings privately while the VM is at
    /// its activation barrier. The listener is bound only after VMGenID has
    /// been acknowledged and the captured workload latch has been released.
    pub(crate) fn new_deferred(
        agent_sock_path: &Path,
        shared: Arc<ConsoleSharedState>,
        bulk_shared: Option<Arc<ConsoleSharedState>>,
    ) -> Self {
        Self {
            shared,
            bulk_shared,
            restored_input: RestoreInput::default(),
            bulk_connection_id: None,
            dual_port_active: false,
            range_lease_active: false,
            listener: None,
            endpoint: agent_sock_path.to_path_buf(),
            ready_frame: None,
            kernel_clock_synchronized: false,
            log_writer: None,
            #[cfg(unix)]
            bind_identity_map: None,
            #[cfg(unix)]
            bind_identity_map_mount_count: 0,
        }
    }

    /// Publish a relay that was constructed behind an activation barrier.
    pub(crate) fn bind_public_endpoint(&mut self) -> RuntimeResult<()> {
        if self.listener.is_some() {
            return Ok(());
        }
        self.listener = Some(AgentListener::bind(&self.endpoint)?);
        tracing::info!(
            "agent relay listening on {} after restore activation",
            self.endpoint.display()
        );
        Ok(())
    }

    /// Attach a log writer for `exec.log` capture.
    ///
    /// Must be called before [`run()`](Self::run). When attached, the
    /// ring reader captures the primary session's stdout/stderr into
    /// the writer's JSON Lines file (see
    /// `design/runtime/sandbox-logs.md` D3 / D3a). The
    /// `--- sandbox started ---` marker is **not** written here — it
    /// is written from [`wait_ready`](Self::wait_ready) once agentd
    /// signals `core.ready`, so the marker only appears when the
    /// guest has actually finished booting.
    pub fn with_log_writer(mut self, writer: Arc<LogWriter>) -> Self {
        self.log_writer = Some(writer);
        self
    }

    /// Attach a pending bind identity map for the early init handshake.
    #[cfg(unix)]
    pub fn with_bind_identity_map(
        mut self,
        handle: Option<BindIdentityMapHandle>,
        mount_count: usize,
    ) -> Self {
        self.bind_identity_map = handle;
        self.bind_identity_map_mount_count = mount_count;
        self
    }

    #[cfg(unix)]
    fn install_bind_identity_map(&self, resolved: InitResolved) -> RuntimeResult<()> {
        let Some(handle) = &self.bind_identity_map else {
            return Ok(());
        };

        // A mount may have pinned an explicit guest owner (`uid=`/`gid=`), which
        // is installed host-side before the guest reports its default user. Keep
        // that value; only fall back to the resolved default user when no
        // explicit owner was set.
        if handle.get().is_some() {
            tracing::info!(
                mounts = self.bind_identity_map_mount_count,
                "agent relay: bind identity map already set by an explicit mount owner"
            );
            return Ok(());
        }

        let host_owner_uid = unsafe { libc::getuid() as u32 };
        let map = BindIdentityMap::new(
            host_owner_uid,
            resolved.default_user.uid,
            resolved.default_user.gid,
        );

        // Ignore a lost race: a concurrent explicit install winning here is fine.
        let _ = handle.set(map);

        tracing::info!(
            host_owner_uid,
            guest_uid = resolved.default_user.uid,
            guest_gid = resolved.default_user.gid,
            mounts = self.bind_identity_map_mount_count,
            "agent relay: installed bind identity maps"
        );

        Ok(())
    }

    fn send_init_ack(&self) -> RuntimeResult<()> {
        let msg = Message::with_payload(MessageType::InitAck, 0, &InitAck {})
            .map_err(|e| RuntimeError::Custom(format!("encode init ack: {e}")))?;
        let mut frame = Vec::new();
        codec::encode_to_buf(&msg, &mut frame)
            .map_err(|e| RuntimeError::Custom(format!("encode init ack frame: {e}")))?;
        push_guest_frame_blocking(&self.shared, frame)
    }

    /// Read frames from the console ring buffer until `core.ready` is
    /// received.
    ///
    /// This is a **blocking** call (uses `libc::poll` on the wake pipe).
    /// Must be called before [`run()`](Self::run). The ready frame is cached
    /// so it can be sent to clients during handshake.
    pub fn wait_ready(&mut self) -> RuntimeResult<()> {
        const READY_TIMEOUT_SECS: i32 = 180;

        let mut buf = BytesMut::new();
        let mut bulk_binding = Vec::with_capacity(BULK_BINDING_SIZE);
        #[cfg(unix)]
        let mut init_resolved = false;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(READY_TIMEOUT_SECS as u64);

        loop {
            // The guest never emits raw records before this fixed-size binding is acknowledged.
            // Drain it before control so a concurrently queued `core.ready` cannot overtake its
            // own physical-lane proof in the host.
            self.try_bind_bulk_port(&mut bulk_binding)?;

            // Drain the wake pipe and pop all available chunks.
            self.shared.tx_wake.drain();
            while let Some(chunk) = self.shared.tx_ring.pop() {
                buf.extend_from_slice(&chunk);
                drop(chunk);
                self.shared.tx_capacity_wake.wake();
            }

            // Try to extract complete frames.
            while let Some(frame) = try_extract_frame(&mut buf)? {
                let msg = decode_frame(frame.data.as_ref())?;

                if msg.t == MessageType::Ready {
                    #[cfg(unix)]
                    if self.bind_identity_map.is_some() && !init_resolved {
                        return Err(RuntimeError::Custom(
                            "agent relay: received core.ready before init context resolution"
                                .into(),
                        ));
                    }
                    let ready: Ready = msg.payload().map_err(|error| {
                        RuntimeError::Custom(format!("decode core.ready payload: {error}"))
                    })?;
                    self.select_ready_transport(&ready)?;
                    tracing::info!(
                        dual_port = self.dual_port_active,
                        "agent relay: received core.ready from agentd"
                    );
                    #[cfg(unix)]
                    let ready = {
                        let mut ready = ready;
                        // This capability describes only the already authenticated local SDK
                        // hop. Agentd remains unaware of shared mappings and the guest generation
                        // stays unchanged.
                        ready.local_transport = Some(LocalTransportReady::shared_arena_v1());
                        ready
                    };
                    // Capture the complete client-facing capability set, including the existing
                    // host-local shared-arena offer, for post-restore handshakes.
                    self.shared.workload_control.install_ready(
                        msg.v,
                        ready.clone(),
                        self.dual_port_active,
                    );
                    let mut client_ready =
                        Message::with_payload(MessageType::Ready, msg.id, &ready).map_err(
                            |error| {
                                RuntimeError::Custom(format!(
                                    "encode SDK-facing core.ready payload: {error}"
                                ))
                            },
                        )?;
                    client_ready.v = msg.v;
                    let mut client_ready_frame = Vec::new();
                    codec::encode_to_buf(&client_ready, &mut client_ready_frame).map_err(
                        |error| {
                            RuntimeError::Custom(format!(
                                "encode SDK-facing core.ready frame: {error}"
                            ))
                        },
                    )?;
                    self.ready_frame = Some(client_ready_frame);
                    // Now that agentd has signalled readiness, mark the
                    // exec.log lifecycle. Doing this here (rather than
                    // in `with_log_writer`) means the marker only shows
                    // up when the guest actually came up — pre-relay
                    // failures (mount errors, etc.) leave exec.log empty
                    // and let `boot-error.json` carry the story alone.
                    if let Some(ref writer) = self.log_writer {
                        writer.write_system("--- sandbox started ---");
                    }
                    return Ok(());
                }

                if msg.t == MessageType::InitResolved {
                    let resolved: InitResolved = msg.payload().map_err(|e| {
                        RuntimeError::Custom(format!("decode init context payload: {e}"))
                    })?;
                    #[cfg(unix)]
                    self.install_bind_identity_map(resolved)?;
                    #[cfg(windows)]
                    let _ = resolved;
                    #[cfg(unix)]
                    {
                        init_resolved = true;
                    }
                    self.send_init_ack()?;
                    continue;
                }

                tracing::debug!(
                    "agent relay: discarding pre-ready frame type={:?} id={}",
                    msg.t,
                    msg.id
                );
            }

            // Check timeout.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::Custom(
                    "agent relay: timed out waiting for core.ready from agentd".into(),
                ));
            }

            // Block until the wake primitive is readable or timeout expires.
            let wait = if self.bulk_shared.is_some() {
                remaining.min(std::time::Duration::from_millis(10))
            } else {
                remaining
            };
            let _ = self.shared.tx_wake.wait_timeout(wait);
        }
    }

    /// Consume and acknowledge the dedicated port's fixed binding prelude when present.
    fn try_bind_bulk_port(&mut self, binding: &mut Vec<u8>) -> RuntimeResult<()> {
        if self.bulk_connection_id.is_some() {
            return Ok(());
        }
        let Some(shared) = self.bulk_shared.as_ref() else {
            return Ok(());
        };

        shared.tx_wake.drain();
        while let Some(chunk) = shared.tx_ring.pop() {
            binding.extend_from_slice(&chunk);
            drop(chunk);
            shared.tx_capacity_wake.wake();
        }
        if binding.len() > BULK_BINDING_SIZE {
            return Err(RuntimeError::Custom(
                "agent relay: bulk port sent data before binding acknowledgement".into(),
            ));
        }
        if binding.len() != BULK_BINDING_SIZE {
            return Ok(());
        }

        let connection_id = decode_bulk_hello(binding)
            .map_err(|error| RuntimeError::Custom(format!("agent relay: {error}")))?;
        push_guest_frame_blocking(shared, encode_bulk_ack(connection_id).to_vec())?;
        self.bulk_connection_id = Some(connection_id);
        tracing::info!("agent relay: bound dedicated agent-bulk port");
        Ok(())
    }

    /// Match the readiness capability to the physical binding or retain combined fallback.
    fn select_ready_transport(&mut self, ready: &Ready) -> RuntimeResult<()> {
        self.range_lease_active = ready
            .relay_lease
            .as_ref()
            .and_then(|capability| capability.select_supported(RELAY_LEASE_FORMAT_V1))
            == Some(RELAY_LEASE_FORMAT_V1);
        match (self.bulk_connection_id, ready.bulk_transport.as_ref()) {
            (Some(connection_id), Some(capability)) => {
                capability
                    .validate_dual_port_v1(connection_id)
                    .map_err(|error| RuntimeError::Custom(format!("agent relay: {error}")))?;
                if !self.range_lease_active {
                    return Err(RuntimeError::Custom(
                        "agent relay: dual-port-v1 requires range-lease-v1".into(),
                    ));
                }
                self.dual_port_active = true;
            }
            (None, None) => {
                self.dual_port_active = false;
                if let Some(shared) = self.bulk_shared.as_ref() {
                    shared.close();
                    tracing::info!(
                        "agent relay: agentd did not bind agent-bulk; using combined transport"
                    );
                }
            }
            (Some(_), None) => {
                return Err(RuntimeError::Custom(
                    "agent relay: bound bulk port missing from core.ready".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(RuntimeError::Custom(
                    "agent relay: core.ready advertised an unbound bulk port".into(),
                ));
            }
        }
        Ok(())
    }

    /// Activate a construction-paused checkpoint before serving public clients.
    ///
    /// The restored agent does not reboot and therefore does not emit another
    /// `core.ready`. This path resumes only the kernel and agentd, waits for the
    /// exact VM Generation ID acknowledgement, releases the captured workload
    /// latch over the private console path, and only then installs the cached
    /// ready frame used by ordinary client handshakes.
    pub(crate) fn activate_restored(
        &mut self,
        vm: &msb_krun::VmControl,
        restored: &RestoredAgentState,
        runtime_dir: &Path,
        startup_progress: &crate::startup_progress::StartupProgressCallback,
    ) -> RuntimeResult<()> {
        let wait_paused_started = Instant::now();
        let paused = vm
            // Vm::enter still has to read RAM and restore CPU/device state. Storage
            // preparation is cancellable by the owning launcher, not an activation
            // timeout. Failures remain errors and never announce readiness.
            .wait_until_paused_without_timeout()
            .map_err(|error| {
                RuntimeError::Custom(format!("wait for restored VM pause: {error}"))
            })?;
        let msb_krun::VmExecutionState::Paused(pause_generation) = paused else {
            return Err(RuntimeError::Custom(
                "restored VM did not reach its construction pause".into(),
            ));
        };
        let wait_paused_us = wait_paused_started.elapsed().as_micros();
        // Keep activation timing separate from construction I/O; wait_paused_us remains
        // available independently for diagnosing slow preparation.
        let total_started = Instant::now();
        startup_progress(crate::startup_progress::StartupProgress::phase(
            crate::startup_progress::StartupPhase::Activating,
        ));
        restored
            .publish_mount_warnings(runtime_dir)
            .map_err(RuntimeError::Custom)?;

        let generation_bytes: [u8; 16] = rand::random();
        let prepared_persist_started = Instant::now();
        persist_restore_activation(
            runtime_dir,
            &restored.attempt_id,
            generation_bytes,
            "prepared",
        )?;
        let prepared_persist_us = prepared_persist_started.elapsed().as_micros();
        let generation_install_started = Instant::now();
        let request = vm
            .install_vm_generation_and_clock(generation_bytes.into())
            .ok_or_else(|| {
                RuntimeError::Custom("restored kernel lacks identity-and-clock activation; recreate this development full snapshot with the updated kernel or use disk-only restore".into())
            })?;
        let generation_install_us = generation_install_started.elapsed().as_micros();
        let resume_started = Instant::now();
        vm.resume(pause_generation).map_err(|error| {
            RuntimeError::Custom(format!("resume restored VM for activation: {error}"))
        })?;
        let resume_us = resume_started.elapsed().as_micros();

        let generation_ack_started = Instant::now();
        match vm.wait_vm_generation_processed(request, RESTORE_ACTIVATION_TIMEOUT) {
            Some(msb_krun::VmGenerationWaitOutcome::Processed) => {}
            Some(msb_krun::VmGenerationWaitOutcome::Failed) => {
                return Err(RuntimeError::Custom("restored kernel rejected identity-and-clock activation; workloads remain frozen".into()));
            }
            Some(msb_krun::VmGenerationWaitOutcome::Superseded) => {
                return Err(RuntimeError::Custom(
                    "restored VM Generation ID request was superseded".into(),
                ));
            }
            Some(msb_krun::VmGenerationWaitOutcome::TimedOut) => {
                return Err(RuntimeError::Custom(
                    "restored VM Generation ID acknowledgement timed out".into(),
                ));
            }
            None => {
                return Err(RuntimeError::Custom(
                    "restored VM Generation ID transport disappeared".into(),
                ));
            }
        }
        let generation_ack_us = generation_ack_started.elapsed().as_micros();
        self.kernel_clock_synchronized = true;

        let ready_started = Instant::now();
        self.install_restored_ready(restored)?;
        let ready_us = ready_started.elapsed().as_micros();
        let thaw_started = Instant::now();
        self.thaw_restored_workload(restored)?;
        let thaw_us = thaw_started.elapsed().as_micros();
        let activated_persist_started = Instant::now();
        persist_restore_activation(
            runtime_dir,
            &restored.attempt_id,
            generation_bytes,
            "activated",
        )?;
        let activated_persist_us = activated_persist_started.elapsed().as_micros();
        if let Some(ref writer) = self.log_writer {
            writer.write_system("--- sandbox restored ---");
        }
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "restore_activate",
            checkpoint_id = restored.attempt_id,
            total_us = total_started.elapsed().as_micros(),
            wait_paused_us,
            prepared_persist_us,
            generation_install_us,
            resume_us,
            generation_ack_us,
            thaw_us,
            ready_us,
            activated_persist_us,
            "checkpoint restore activation timing"
        );
        Ok(())
    }

    fn thaw_restored_workload(&mut self, restored: &RestoredAgentState) -> RuntimeResult<()> {
        if !self.restored_input.control.is_empty() || !self.restored_input.bulk.is_empty() {
            return Err(RuntimeError::Custom(
                "restored transport did not start at a complete-frame boundary".into(),
            ));
        }
        self.shared
            .workload_control
            .restore(
                restored.host_input,
                restored.input_credit,
                restored.guest_bulk_bytes_target,
            )
            .map_err(RuntimeError::Custom)?;
        let mut request = Message::with_payload(
            MessageType::WorkloadThaw,
            RESTORE_CONTROL_ID,
            &WorkloadThaw {
                attempt_id: restored.attempt_id.clone(),
                mode: microsandbox_protocol::core::WorkloadThawMode::Restore,
            },
        )
        .map_err(|error| RuntimeError::Custom(format!("encode restored workload thaw: {error}")))?;
        request.v = restored.protocol_generation;
        let mut frame = Vec::new();
        codec::encode_to_buf(&request, &mut frame).map_err(|error| {
            RuntimeError::Custom(format!("encode restored workload thaw frame: {error}"))
        })?;
        let mut pending_request = Some(Bytes::from(frame));

        let deadline = std::time::Instant::now() + RESTORE_ACTIVATION_TIMEOUT;
        let mut input = std::mem::take(&mut self.restored_input.control);
        loop {
            // Drain old bulk records while the guest waits for its scheduler cut. Preserve any
            // partial final record for the ordinary reader; never restart decoding mid-frame.
            if let Some(shared) = &self.bulk_shared {
                let bytes = drain_restored_bulk(shared, &mut self.restored_input.bulk)?;
                self.shared
                    .workload_control
                    .observed_bulk(bytes, self.restored_input.bulk.len())
                    .map_err(RuntimeError::Custom)?;
            }
            if let Some(frame) = pending_request.take() {
                match self.shared.rx_ring.push(frame) {
                    Ok(()) => self.shared.rx_wake.wake(),
                    Err(frame) => pending_request = Some(frame),
                }
            }
            self.shared.tx_wake.drain();
            while let Some(chunk) = self.shared.tx_ring.pop() {
                input.extend_from_slice(&chunk);
                drop(chunk);
                self.shared.tx_capacity_wake.wake();
            }
            loop {
                if try_decode_relay_client_disconnected_ack_from_bytes(&mut input)
                    .map_err(|error| {
                        RuntimeError::Custom(format!("restore disconnect acknowledgement: {error}"))
                    })?
                    .is_some()
                {
                    continue;
                }
                let Some(frame) = try_extract_frame(&mut input)? else {
                    break;
                };
                // Combined-mode stale bulk is opaque, not a CBOR control message.
                if frame.flags == FLAG_BULK {
                    continue;
                }
                let message = decode_frame(frame.data.as_ref())?;
                if message.id != RESTORE_CONTROL_ID {
                    tracing::debug!(
                        message_type = message.t.as_str(),
                        id = message.id,
                        "discarding pre-activation restored-agent frame"
                    );
                    continue;
                }
                if message.t == MessageType::CoreError {
                    let error = message.payload::<CoreError>().map_err(|decode| {
                        RuntimeError::Custom(format!(
                            "decode restored workload thaw error: {decode}"
                        ))
                    })?;
                    return Err(RuntimeError::Custom(format!(
                        "restored workload thaw rejected: {}",
                        error.message
                    )));
                }
                if message.t == MessageType::WorkloadTransportCredit {
                    self.shared
                        .workload_control
                        .reply(message)
                        .map_err(RuntimeError::Custom)?;
                    continue;
                }
                if message.t != MessageType::WorkloadThawed {
                    return Err(RuntimeError::Custom(format!(
                        "unexpected restored workload reply {}",
                        message.t.as_str()
                    )));
                }
                let thawed = message.payload::<WorkloadThawed>().map_err(|error| {
                    RuntimeError::Custom(format!("decode restored workload thaw: {error}"))
                })?;
                if thawed.attempt_id != restored.attempt_id {
                    return Err(RuntimeError::Custom(
                        "restored workload thaw belongs to another checkpoint attempt".into(),
                    ));
                }
                self.restored_input.control = input;
                return Ok(());
            }

            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::Custom(
                    "restored workload thaw timed out".into(),
                ));
            }
            let wait = if self.bulk_shared.is_some() || pending_request.is_some() {
                remaining.min(std::time::Duration::from_millis(10))
            } else {
                remaining
            };
            let _ = self.shared.tx_wake.wait_timeout(wait);
        }
    }

    fn install_restored_ready(&mut self, restored: &RestoredAgentState) -> RuntimeResult<()> {
        // Guest RAM already contains the completed bulk binding: no new boot hello is sent.
        if restored.ready.bulk_transport.is_some() && self.bulk_shared.is_none() {
            return Err(RuntimeError::Custom(
                "restored agent requires its captured bulk console lane".into(),
            ));
        }
        self.bulk_connection_id = restored
            .ready
            .bulk_transport
            .as_ref()
            .map(|ready| ready.connection_id);
        self.select_ready_transport(&restored.ready)?;
        self.shared.workload_control.install_ready(
            restored.protocol_generation,
            restored.ready.clone(),
            self.dual_port_active,
        );
        let mut ready = Message::with_payload(MessageType::Ready, 0, &restored.ready)
            .map_err(|error| RuntimeError::Custom(format!("encode restored ready: {error}")))?;
        ready.v = restored.protocol_generation;
        let mut frame = Vec::new();
        codec::encode_to_buf(&ready, &mut frame).map_err(|error| {
            RuntimeError::Custom(format!("encode restored ready frame: {error}"))
        })?;
        self.ready_frame = Some(frame);
        Ok(())
    }

    /// Run the main relay loop.
    ///
    /// Accepts client connections, relays frames between clients and the
    /// console ring buffers, and handles client disconnects with session
    /// cleanup.
    ///
    /// When a client sends a `core.shutdown` message (identified by
    /// `FLAG_SHUTDOWN` in the frame header), the relay notifies the caller
    /// via `drain_tx` after forwarding the frame to agentd. The caller is
    /// expected to give agentd a flush window before forcing host-side
    /// teardown.
    pub async fn run(
        mut self,
        mut shutdown: watch::Receiver<bool>,
        drain_tx: mpsc::Sender<()>,
    ) -> RuntimeResult<()> {
        let ready_frame = self.ready_frame.take().ok_or_else(|| {
            RuntimeError::Custom("agent relay: run() called before wait_ready()".into())
        })?;

        let mut listener = self
            .listener
            .take()
            .ok_or_else(|| RuntimeError::Custom("agent relay: endpoint not published".into()))?;

        // Shared state: map from client slot index to client state.
        let clients: Arc<Mutex<HashMap<u32, ClientState>>> = Arc::new(Mutex::new(HashMap::new()));

        // Bounded channel for client reader tasks to send frames to the ring writer.
        // Backpressure prevents unbounded memory growth from client floods.
        let (agent_tx, agent_rx) = ControlWriter::new();
        self.shared
            .workload_control
            .register_ordinary_writer(agent_tx.clone());

        // Track which client slots are in use.
        let used_slots: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        // A slot remains in `used_slots` until agentd acknowledges its disconnect on the reverse
        // control stream. Incarnations protect the independent bulk lane; this map protects the
        // intentionally untagged generation-8 control stream from premature range reuse.
        let pending_disconnects: Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn the ring writer task (client frames → rx_ring → guest).
        let shared_for_writer = Arc::clone(&self.shared);
        let mut ring_writer_handle = tokio::spawn(ring_writer_task(shared_for_writer, agent_rx));
        let clock_sync_handle =
            spawn_clock_sync_task(agent_tx.clone(), self.kernel_clock_synchronized);
        let bulk_write_budget = self
            .dual_port_active
            .then(|| Arc::new(Semaphore::new(BULK_WRITE_BYTE_CAPACITY)));
        let (bulk_failure_tx, mut bulk_failure_rx) = mpsc::channel::<RuntimeResult<()>>(1);
        let (bulk_tx, bulk_writer_handle) = if self.dual_port_active {
            let shared = self
                .bulk_shared
                .as_ref()
                .expect("bound dual port has shared state")
                .clone();
            let (tx, rx) = mpsc::channel::<BulkWriterCommand>(256);
            let failure_tx = bulk_failure_tx.clone();
            let workload = Arc::clone(&self.shared.workload_control);
            let handle = tokio::spawn(async move {
                let _ = failure_tx
                    .send(bulk_ring_writer_task(shared, rx, workload).await)
                    .await;
            });
            (Some(tx), Some(handle))
        } else {
            (None, None)
        };

        // Spawn the ring reader task (tx_ring → guest frames → clients).
        // When a log writer is attached, the reader also captures
        // every exec session's stdout/stderr into `exec.log` (tagged
        // with a relay-monotonic session id so readers can group or
        // filter by session — the protocol correlation id can be
        // reused across slot recycling, so we mint our own).
        //
        // `session_registry` is shared between the per-client reader
        // (records pty flag and assigns the monotonic id from
        // `next_session_id` on observed ExecRequest payloads) and
        // the ring reader's tap (looks up the session info for each
        // Exec* frame).
        let session_registry: Arc<SessionRegistry> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (merge_command_tx, merge_command_rx) = mpsc::channel::<MergeCommand>(128);
        // Counter starts at 1 so 0 is unambiguously "not a session"
        // for any out-of-band tooling that might compare against it.
        let next_session_id: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
        let clients_for_reader = Arc::clone(&clients);
        let shared_for_reader = Arc::clone(&self.shared);
        let log_writer_for_reader = self.log_writer.clone();
        let registry_for_reader = Arc::clone(&session_registry);
        let mut ring_reader_handle = tokio::spawn(ring_reader_task(
            shared_for_reader,
            self.dual_port_active
                .then(|| self.bulk_shared.as_ref().expect("bound bulk state").clone()),
            self.range_lease_active,
            merge_command_rx,
            RingReaderContext {
                initial: std::mem::take(&mut self.restored_input),
                clients: clients_for_reader,
                log_writer: log_writer_for_reader,
                session_registry: registry_for_reader,
                pending_disconnects: Arc::clone(&pending_disconnects),
                bulk_writer: bulk_tx.clone(),
            },
        ));

        // Accept loop.
        let RelayExit {
            failure: relay_failure,
            control_writer_usable,
            can_observe_failure_terminals,
        } = loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok(stream) => {
                            // Refuse new clients during physical input saturation without
                            // disturbing existing requests, output, or lifecycle controls.
                            if input_is_stalled(&self.shared, self.bulk_shared.as_deref()) {
                                drop(stream);
                                continue;
                            }

                            // Allocate a client slot.
                            let slot = {
                                let mut slots = used_slots.lock().await;
                                let mut found = None;
                                for i in 0..AGENT_RELAY_MAX_CLIENTS {
                                    if !slots.contains(&i) {
                                        slots.insert(i);
                                        found = Some(i);
                                        break;
                                    }
                                }
                                found
                            };

                            let slot = match slot {
                                Some(s) => s,
                                None => {
                                    tracing::error!("agent relay: max clients reached, rejecting connection");
                                    drop(stream);
                                    continue;
                                }
                            };

                            let (id_start, id_end_exclusive) = relay_client_id_range(slot)
                                .expect("allocated relay slot has a canonical range");
                            let incarnation = if self.range_lease_active {
                                Some(
                                    random_unused_client_incarnation(
                                        &clients,
                                        &pending_disconnects,
                                    )
                                    .await,
                                )
                            } else {
                                None
                            };
                            tracing::info!(
                                "agent relay: client connected slot={slot} id_start={id_start} id_end_exclusive={id_end_exclusive}"
                            );

                            // Duplicate the descriptor before the guest learns this incarnation.
                            // Once RelayClientConnected is admitted, every local failure must use
                            // the acknowledged disconnect path before the slot can be recycled.
                            #[cfg(unix)]
                            let ancillary_fd = match stream.as_fd().try_clone_to_owned() {
                                Ok(fd) => fd,
                                Err(error) => {
                                    tracing::error!(%error, "agent relay: duplicate client socket for local transport failed");
                                    used_slots.lock().await.remove(&slot);
                                    drop(stream);
                                    continue;
                                }
                            };

                            // Establish the dual-port range owner on the ordered control lane before
                            // the SDK sees its handshake and can submit work on either physical lane.
                            if let Some(incarnation) = incarnation
                                && let Err(error) = tokio::select! {
                                    result = send_relay_client_connected(
                                        &agent_tx, id_start, id_end_exclusive, incarnation,
                                    ) => result,
                                    _ = wait_for_input_stall(&self.shared, self.bulk_shared.as_deref()) => {
                                        Err(RuntimeError::Custom("agent relay: input stalled during client admission".into()))
                                    }
                                }
                            {
                                tracing::error!(%error, "agent relay: failed to establish client incarnation");
                                used_slots.lock().await.remove(&slot);
                                drop(stream);
                                continue;
                            }

                            // Perform handshake: send
                            // [id_start: u32 BE][id_end_exclusive: u32 BE][ready_frame_bytes...].
                            let (reader_half, mut writer_half) = tokio::io::split(stream);
                            let (disconnect_tx, disconnect_rx) = watch::channel(false);

                            let mut handshake = Vec::with_capacity(8 + ready_frame.len());
                            handshake.extend_from_slice(&id_start.to_be_bytes());
                            handshake.extend_from_slice(&id_end_exclusive.to_be_bytes());
                            handshake.extend_from_slice(&ready_frame);

                            if let Err(e) = writer_half.write_all(&handshake).await {
                                tracing::error!(
                                    "agent relay: handshake write failed slot={slot}: {e}"
                                );
                                match begin_relay_client_disconnect(
                                    &agent_tx,
                                    &pending_disconnects,
                                    id_start,
                                    id_end_exclusive,
                                    incarnation,
                                )
                                .await
                                {
                                    Ok(Some(disconnect_ack)) => {
                                        let used_slots = Arc::clone(&used_slots);
                                        tokio::spawn(async move {
                                            if disconnect_ack.await.is_ok() {
                                                used_slots.lock().await.remove(&slot);
                                            } else {
                                                tracing::error!(
                                                    "agent relay: failed handshake slot={slot} remains quarantined"
                                                );
                                            }
                                        });
                                    }
                                    Ok(None) => {
                                        used_slots.lock().await.remove(&slot);
                                    }
                                    Err(error) => {
                                        tracing::error!(
                                            %error,
                                            "agent relay: failed handshake disconnect was not admitted; slot={slot} remains quarantined"
                                        );
                                    }
                                }
                                continue;
                            }

                            // Spawn a per-client writer task so the ring reader
                            // never holds the mutex across async writes.
                            // The mailbox is item-unbounded but byte-bounded by permits carried by
                            // every entry. This keeps routing nonblocking without allowing a burst
                            // of three frames to be mistaken for a stalled SDK client.
                            let (write_tx, write_rx) = mpsc::unbounded_channel::<ClientWrite>();
                            #[cfg(unix)]
                            let (local_write_tx, local_write_rx) =
                                mpsc::unbounded_channel::<LocalClientWrite>();
                            let writer_disconnect_tx = disconnect_tx.clone();
                            tokio::spawn(client_writer_task(
                                slot,
                                writer_half,
                                write_rx,
                                writer_disconnect_tx,
                                #[cfg(unix)]
                                local_write_rx,
                                #[cfg(unix)]
                                ancillary_fd,
                            ));

                            let active_bulk = Arc::new(std::sync::Mutex::new(HashMap::new()));
                            let write_budget = Arc::new(Semaphore::new(
                                CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY,
                            ));

                            // Register the client.
                            {
                                let mut map = clients.lock().await;
                                map.insert(slot, ClientState {
                                    incarnation,
                                    active_sessions: HashSet::new(),
                                    active_bulk: Arc::clone(&active_bulk),
                                    write_tx: write_tx.clone(),
                                    write_budget: Arc::clone(&write_budget),
                                    disconnect_tx,
                                    #[cfg(unix)]
                                    local_outbound: None,
                                });
                            }

                            // Spawn a reader task for this client.
                            let agent_tx_clone = agent_tx.clone();
                            let clients_clone = Arc::clone(&clients);
                            let used_slots_clone = Arc::clone(&used_slots);
                            let drain_tx_clone = drain_tx.clone();
                            let registry_clone = Arc::clone(&session_registry);
                            let next_id_clone = Arc::clone(&next_session_id);
                            let bulk_tx_clone = bulk_tx.clone();
                            let bulk_budget_clone = bulk_write_budget.as_ref().map(Arc::clone);
                            let merge_command_tx_clone = merge_command_tx.clone();
                            let pending_disconnects_clone = Arc::clone(&pending_disconnects);

                            tokio::spawn(client_reader_task(
                                slot,
                                reader_half,
                                agent_tx_clone,
                                clients_clone,
                                used_slots_clone,
                                drain_tx_clone,
                                registry_clone,
                                next_id_clone,
                                bulk_tx_clone,
                                bulk_budget_clone,
                                merge_command_tx_clone,
                                pending_disconnects_clone,
                                id_start,
                                id_end_exclusive,
                                incarnation,
                                active_bulk,
                                write_tx,
                                write_budget,
                                disconnect_rx,
                                Arc::clone(&self.shared.resident_paused),
                                #[cfg(unix)]
                                local_write_tx,
                            ));
                        }
                        Err(e) => {
                            tracing::error!("agent relay: accept error: {e}");
                        }
                    }
                }
                exit = wait_relay_exit(
                    &mut ring_reader_handle,
                    &mut ring_writer_handle,
                    &mut bulk_failure_rx,
                    &mut shutdown,
                ) => {
                    break exit;
                }
            }
        };

        if relay_failure.is_some() && control_writer_usable {
            match tokio::time::timeout(
                RELAY_FAILURE_CLEANUP_TIMEOUT,
                handle_relay_transport_failure(
                    &agent_tx,
                    &merge_command_tx,
                    &clients,
                    can_observe_failure_terminals,
                ),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "agent relay: typed transport-failure cleanup failed");
                }
                Err(_) => {
                    tracing::warn!("agent relay: typed transport-failure cleanup timed out");
                }
            }
        }

        // The "--- sandbox stopped ---" marker is written by the VMM's
        // `on_exit` observer (runs before `_exit()`), so we don't
        // double-write it here.

        // Clean up the local IPC endpoint.
        listener.cleanup(&self.endpoint);

        // Wake any libkrun or relay producer blocked on console capacity.
        self.shared.close();
        if let Some(shared) = self.bulk_shared.as_ref() {
            shared.close();
        }

        // Abort background tasks.
        clock_sync_handle.abort();
        ring_writer_handle.abort();
        if let Some(handle) = bulk_writer_handle {
            handle.abort();
        }
        ring_reader_handle.abort();

        match relay_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AgentRelay {
    fn drop(&mut self) {
        // The console write-capacity hook may be sleeping on a libkrun thread. Every relay exit,
        // including readiness failure or task cancellation, must wake it before VM teardown.
        self.shared.close();
        if let Some(shared) = self.bulk_shared.as_ref() {
            shared.close();
        }
        if let Some(listener) = &self.listener {
            listener.cleanup(&self.endpoint);
        }
        let guest_to_host = self.shared.tx_ring.snapshot();
        let host_to_guest = self.shared.rx_ring.snapshot();
        tracing::debug!(
            guest_to_host_high_water = guest_to_host.high_water_bytes,
            guest_to_host_full_events = guest_to_host.full_events,
            host_to_guest_high_water = host_to_guest.high_water_bytes,
            host_to_guest_full_events = host_to_guest.full_events,
            "agent relay console queue summary"
        );
    }
}

impl From<Bytes> for ControlWrite {
    fn from(data: Bytes) -> Self {
        let uses_data_credit = data.get(LEN_PREFIX_SIZE + 4) == Some(&FLAG_BULK);
        Self {
            data,
            completion: None,
            uses_data_credit,
            order: ControlOrder::GlobalFence,
            admission: None,
        }
    }
}

impl Drop for WorkloadWriterGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn push_guest_frame_blocking(
    shared: &ConsoleSharedState,
    frame: Vec<u8>,
) -> RuntimeResult<()> {
    push_guest_frame_until(shared, frame, std::time::Duration::from_secs(60))
}

/// Discard complete pre-activation records, retaining a possible fragmented tail.
fn drain_restored_bulk(shared: &ConsoleSharedState, input: &mut BytesMut) -> RuntimeResult<usize> {
    let mut decoded_bytes = 0;
    shared.tx_wake.drain();
    while let Some(chunk) = shared.tx_ring.pop() {
        input.extend_from_slice(&chunk);
        drop(chunk);
        shared.tx_capacity_wake.wake();
        while let Some(decoded) = try_decode_incarnated_bulk_from_bytes(input)
            .map_err(|error| RuntimeError::Custom(format!("restored bulk framing: {error}")))?
        {
            decoded_bytes += CLIENT_INCARNATION_SIZE + decoded.frame.len();
        }
    }
    Ok(decoded_bytes)
}

fn persist_restore_activation(
    runtime_dir: &Path,
    attempt_id: &str,
    generation_id: [u8; 16],
    state: &str,
) -> RuntimeResult<()> {
    use std::io::Write as _;

    let target = runtime_dir.join("restore-activation.json");
    let temporary = runtime_dir.join(format!(".restore-activation.{}.tmp", rand::random::<u64>()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    serde_json::to_writer(
        &mut file,
        &RestoreActivationRecord {
            attempt_id,
            vm_generation_id: hex::encode(generation_id),
            state,
        },
    )
    .map_err(|error| RuntimeError::Custom(format!("encode restore activation: {error}")))?;
    file.write_all(b"\n")?;
    // Diagnostic only: the live activation barrier, not this record, controls readiness.
    drop(file);
    crate::checkpoint::replace_file(&temporary, &target)?;
    Ok(())
}

pub(crate) fn push_guest_frame_until(
    shared: &ConsoleSharedState,
    frame: Vec<u8>,
    timeout: std::time::Duration,
) -> RuntimeResult<()> {
    if let Some(writer) = shared
        .workload_control
        .ordinary_writer()
        .map_err(RuntimeError::Custom)?
    {
        return push_ordered_guest_frame_until(shared, &writer, Bytes::from(frame), timeout);
    }
    let deadline = std::time::Instant::now() + timeout;
    let mut frame = Bytes::from(frame);

    loop {
        match shared.rx_ring.push(frame) {
            Ok(()) => {
                shared.rx_wake.wake();
                return Ok(());
            }
            Err(returned) => {
                frame = returned;
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(RuntimeError::Custom(
                        "timed out sending frame to agentd".into(),
                    ));
                }

                // Drain then re-check to avoid losing a capacity transition racing the wait.
                shared.rx_capacity_wake.drain();
                if shared.rx_ring.can_fit(frame.len()) {
                    continue;
                }
                let _ = shared.rx_capacity_wake.wait_timeout(remaining);
            }
        }
    }
}

/// Await the same ordered admission without occupying the worker that must run the writer.
///
/// The receipt acknowledges a push into the guest transport, not guest shutdown completion.
/// Timing out after queue acceptance does not retract the frame: the existing writer still owns it.
pub(crate) async fn push_guest_frame_until_async(
    shared: &Arc<ConsoleSharedState>,
    frame: Vec<u8>,
    timeout: std::time::Duration,
) -> RuntimeResult<()> {
    let Some(writer) = shared
        .workload_control
        .ordinary_writer()
        .map_err(RuntimeError::Custom)?
    else {
        // Preserve bootstrap's pre-Ready path without blocking an async worker. Recheck readiness
        // inside the synchronous helper, since Ready may arrive before this offload starts.
        // Once dispatched, this bounded offload owns the request even if its waiter is canceled.
        let shared = Arc::clone(shared);
        return tokio::task::spawn_blocking(move || {
            push_guest_frame_until(&shared, frame, timeout)
        })
        .await
        .map_err(|error| RuntimeError::Custom(format!("guest frame sender failed: {error}")))?;
    };
    let (completion, completed) = oneshot::channel();
    let write = ControlWrite {
        completion: Some(completion),
        ..Bytes::from(frame).into()
    };
    // One deadline includes both bounded-queue admission and physical delivery. Keeping the
    // ordinary writer preserves its global fence, pause gate, and transport-credit accounting.
    tokio::time::timeout(timeout, async {
        writer
            .send(write)
            .await
            .map_err(|_| RuntimeError::Custom("agent control writer stopped".into()))?;
        completed.await.map_err(|_| {
            RuntimeError::Custom("agent control writer dropped admission receipt".into())
        })
    })
    .await
    .map_err(|_| RuntimeError::Custom("timed out sending ordered frame to agentd".into()))?
}

/// The parent-watch thread is synchronous. Reuse the ordinary queue and its admission receipt
/// without bypassing a frozen/credit-starved FIFO head. Async callers must use the async helper.
fn push_ordered_guest_frame_until(
    shared: &ConsoleSharedState,
    writer: &ControlWriter,
    data: Bytes,
    timeout: std::time::Duration,
) -> RuntimeResult<()> {
    let deadline = Instant::now() + timeout;
    let (completion, mut completed) = oneshot::channel();
    let mut pending = Some(ControlWrite {
        completion: Some(completion),
        ..data.into()
    });
    loop {
        if let Some(write) = pending.take() {
            match writer.try_send(write) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(write)) => pending = Some(write),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(RuntimeError::Custom("agent control writer stopped".into()));
                }
            }
        }
        match completed.try_recv() {
            Ok(()) => return Ok(()),
            Err(oneshot::error::TryRecvError::Closed) => {
                return Err(RuntimeError::Custom(
                    "agent control writer dropped admission receipt".into(),
                ));
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || shared.is_closed() {
            return Err(RuntimeError::Custom(
                "timed out sending ordered frame to agentd".into(),
            ));
        }
        // This rare synchronous shutdown path polls its receipt at a bounded interval using the
        // existing capacity wake. No new socket, queue or background waiter is introduced.
        let _ = shared
            .rx_capacity_wake
            .wait_timeout(remaining.min(std::time::Duration::from_millis(10)));
    }
}

/// Try to extract a complete frame from a byte buffer.
///
/// Returns `None` if the buffer doesn't contain a full frame yet. On
/// success, the consumed bytes are removed from `buf`.
fn try_extract_frame(buf: &mut BytesMut) -> RuntimeResult<Option<RawFrame>> {
    if buf.len() < LEN_PREFIX_SIZE {
        return Ok(None);
    }

    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Sanity checks.
    if frame_len > MAX_FRAME_SIZE as usize {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too large: {frame_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    if buf.len() < LEN_PREFIX_SIZE + frame_len {
        return Ok(None); // Need more data.
    }

    if frame_len < FRAME_HEADER_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too short: {frame_len} bytes"
        )));
    }

    // Split off the complete frame — zero-copy via freeze().
    let data = buf.split_to(LEN_PREFIX_SIZE + frame_len).freeze();

    let id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let flags = data[8];

    Ok(Some(RawFrame { data, id, flags }))
}

/// Decode raw frame bytes into a protocol `Message`.
fn decode_frame(buf: &[u8]) -> RuntimeResult<Message> {
    codec::decode_message_frame(buf).map_err(|e| RuntimeError::Custom(format!("decode frame: {e}")))
}

/// Drain one client's priority local commands and ordinary frame batches through one writer.
async fn client_writer_task<W>(
    slot: u32,
    mut writer: W,
    mut write_rx: mpsc::UnboundedReceiver<ClientWrite>,
    disconnect_tx: watch::Sender<bool>,
    #[cfg(unix)] mut local_write_rx: mpsc::UnboundedReceiver<LocalClientWrite>,
    #[cfg(unix)] ancillary_fd: OwnedFd,
) where
    W: AsyncWrite + Unpin,
{
    let mut batch = VecDeque::new();
    let mut deferred = None;
    #[cfg(unix)]
    let mut local_commands_open = true;
    loop {
        #[cfg(unix)]
        if local_commands_open {
            match local_write_rx.try_recv() {
                Ok(command) => {
                    if let Err(error) =
                        write_local_client_command(&mut writer, &ancillary_fd, command).await
                    {
                        tracing::error!(
                            "agent relay: local client writer slot={slot} failed: {error}"
                        );
                        let _ = disconnect_tx.send(true);
                        break;
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => local_commands_open = false,
            }
        }

        let write = match deferred.take() {
            Some(write) => write,
            None => {
                #[cfg(unix)]
                {
                    tokio::select! {
                        biased;
                        command = local_write_rx.recv(), if local_commands_open => {
                            let Some(command) = command else {
                                // Once the reader side is gone, stop polling a permanently-ready
                                // closed priority channel so the ordinary writer can drain and exit.
                                local_commands_open = false;
                                continue;
                            };
                            if let Err(error) = write_local_client_command(
                                &mut writer,
                                &ancillary_fd,
                                command,
                            ).await {
                                tracing::error!("agent relay: local client writer slot={slot} failed: {error}");
                                let _ = disconnect_tx.send(true);
                                break;
                            }
                            continue;
                        }
                        write = write_rx.recv() => {
                            let Some(write) = write else { break; };
                            write
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    let Some(write) = write_rx.recv().await else {
                        break;
                    };
                    write
                }
            }
        };
        let mut batch_bytes = match &write.data {
            ClientWriteData::Inline(data) => data.len(),
            #[cfg(unix)]
            ClientWriteData::LocalBulk(_) => {
                if let Err(error) = write_ordered_local_bulk(&mut writer, write).await {
                    tracing::error!("agent relay: local bulk writer slot={slot} failed: {error}");
                    let _ = disconnect_tx.send(true);
                    break;
                }
                continue;
            }
        };
        batch.push_back(write);
        while batch.len() < CLIENT_WRITE_BATCH_FRAMES && batch_bytes < CLIENT_WRITE_BATCH_BYTES {
            let Ok(write) = write_rx.try_recv() else {
                break;
            };
            let Some(data) = write.data.inline() else {
                // A local descriptor is an ordering barrier: flush every preceding in-band frame
                // before publishing its arena slot to the SDK.
                deferred = Some(write);
                break;
            };
            if batch_bytes.saturating_add(data.len()) > CLIENT_WRITE_BATCH_BYTES {
                deferred = Some(write);
                break;
            }
            batch_bytes = batch_bytes.saturating_add(data.len());
            batch.push_back(write);
        }

        if let Err(error) = write_client_batch(&mut writer, &mut batch).await {
            tracing::error!("agent relay: client writer slot={slot} failed: {error}");
            let _ = disconnect_tx.send(true);
            break;
        }
    }
}

#[cfg(unix)]
async fn write_local_client_command<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ancillary_fd: &OwnedFd,
    command: LocalClientWrite,
) -> Result<(), String> {
    match command {
        LocalClientWrite::Upgrade { server, completion } => {
            let result = async {
                tokio::time::timeout(CLIENT_OUTPUT_STALL_GRACE, writer.flush())
                    .await
                    .map_err(|_| "flush before shared-arena acknowledgement timed out".to_string())?
                    .map_err(|error| error.to_string())?;
                tokio::time::timeout(
                    CLIENT_OUTPUT_STALL_GRACE,
                    send_local_shm_upgrade_fd(ancillary_fd.as_raw_fd(), Some(server.client_fds())),
                )
                .await
                .map_err(|_| "shared-arena descriptor send timed out".to_string())?
                .map_err(|error| error.to_string())
            }
            .await;
            let failed = result.as_ref().err().cloned();
            let _ = completion.send(result);
            if let Some(error) = failed {
                return Err(error);
            }
        }
        LocalClientWrite::Release(release) => {
            let wire = encode_local_bulk_release(release).map_err(|e| e.to_string())?;
            write_local_client_bytes(writer, &wire).await?;
        }
    }
    Ok(())
}

/// Publish one shared-arena descriptor at its exact position in the merged guest output stream.
#[cfg(unix)]
async fn write_ordered_local_bulk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    write: ClientWrite,
) -> Result<(), String> {
    let ClientWriteData::LocalBulk(mut prepared) = write.data else {
        return Err("ordered local bulk writer received an in-band frame".to_string());
    };
    let wire = encode_local_bulk_ref(prepared.descriptor()).map_err(|e| e.to_string())?;
    write_local_client_bytes(writer, &wire).await?;
    prepared.commit();
    Ok(())
}

#[cfg(unix)]
async fn write_local_client_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), String> {
    tokio::time::timeout(CLIENT_OUTPUT_STALL_GRACE, writer.write_all(bytes))
        .await
        .map_err(|_| "local descriptor write timed out".to_string())?
        .map_err(|error| error.to_string())?;
    tokio::time::timeout(CLIENT_OUTPUT_STALL_GRACE, writer.flush())
        .await
        .map_err(|_| "local descriptor flush timed out".to_string())?
        .map_err(|error| error.to_string())
}

/// Write a client batch with cursor advancement so short writes never compact frame tails.
async fn write_client_batch<W: AsyncWrite + Unpin>(
    writer: &mut W,
    batch: &mut VecDeque<ClientWrite>,
) -> std::io::Result<()> {
    while !batch.is_empty() {
        let slices: Vec<IoSlice<'_>> = batch
            .iter()
            .take(CLIENT_WRITE_BATCH_FRAMES)
            .map(|write| {
                let Some(data) = write.data.inline() else {
                    unreachable!("local bulk descriptors are ordering barriers, never batch data")
                };
                IoSlice::new(data)
            })
            .collect();
        let written =
            tokio::time::timeout(CLIENT_OUTPUT_STALL_GRACE, writer.write_vectored(&slices))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "SDK client output made no write progress",
                    )
                })??;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }

        let mut remaining = written;
        while remaining != 0 {
            let front = batch.front_mut().expect("non-empty batch after write");
            let Some(data) = front.data.inline_mut() else {
                unreachable!("local bulk descriptors are ordering barriers, never batch data")
            };
            if remaining < data.len() {
                data.advance(remaining);
                remaining = 0;
            } else {
                remaining -= data.len();
                batch.pop_front();
            }
        }
    }
    tokio::time::timeout(CLIENT_OUTPUT_STALL_GRACE, writer.flush())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SDK client output flush made no progress",
            )
        })?
}

/// Tap a guest-originated frame into `exec.log` if it belongs to the
/// primary session. Best-effort: any decode error is logged and
/// dropped — capture failures must never disrupt the routing path.
fn tap_frame_into_log(frame: &RawFrame, writer: &LogWriter, session_registry: &SessionRegistry) {
    // Decode the message envelope to learn the type. The full CBOR
    // decode is small (the envelope is a 3-field map; the heavy
    // payload is left as opaque bytes in `Message::p`).
    let msg = match decode_frame(frame.data.as_ref()) {
        Ok(m) => m,
        Err(err) => {
            tracing::debug!(error = %err, "exec_log: skipping frame with decode error");
            return;
        }
    };

    // Look up the session info recorded by `client_reader_task` when
    // the ExecRequest arrived. Returns `None` for frames whose
    // session predates the relay's lifetime or whose ExecRequest
    // we missed (defensive — shouldn't happen in normal operation).
    let session_info = session_registry
        .lock()
        .ok()
        .and_then(|m| m.get(&msg.id).copied());

    match msg.t {
        // ExecRequest flows host→guest, observed in `client_reader_task`.
        MessageType::ExecStdout => {
            let Some(info) = session_info else { return };
            // pty mode merges stdout+stderr into a single stream
            // shipped over ExecStdout frames; tag as `Output`
            // accordingly.
            let tag = if info.is_pty {
                LogSource::Output
            } else {
                LogSource::Stdout
            };
            match msg.payload::<ExecStdout>() {
                Ok(p) => writer.write_chunk(tag, info.session_id, &p.data),
                Err(err) => tracing::debug!(error = %err, "exec_log: stdout payload decode failed"),
            }
        }
        MessageType::ExecStderr => {
            // ExecStderr frames are pipe-mode-only by construction.
            let Some(info) = session_info else { return };
            match msg.payload::<ExecStderr>() {
                Ok(p) => writer.write_chunk(LogSource::Stderr, info.session_id, &p.data),
                Err(err) => tracing::debug!(error = %err, "exec_log: stderr payload decode failed"),
            }
        }
        _ => {}
    }

    // Drop the registry entry on any terminal frame (ExecExited,
    // ExecFailed) so we don't leak `SessionInfo` for the lifetime of
    // the relay. The flag is set on both — checking it here covers
    // every terminal exec frame uniformly.
    if (frame.flags & FLAG_TERMINAL) != 0
        && let Ok(mut registry) = session_registry.lock()
    {
        registry.remove(&msg.id);
    }
}

/// Prefer completed tasks over simultaneous shutdown so genuine failures are retained.
/// Keeping this selection together also makes each completion path independently testable.
async fn wait_relay_exit(
    reader: &mut tokio::task::JoinHandle<RuntimeResult<()>>,
    writer: &mut tokio::task::JoinHandle<RuntimeResult<()>>,
    bulk: &mut mpsc::Receiver<RuntimeResult<()>>,
    shutdown: &mut watch::Receiver<bool>,
) -> RelayExit {
    loop {
        let (result, name, control_writer_usable, can_observe_failure_terminals) = tokio::select! {
            biased;
            result = &mut *reader => (
                result.unwrap_or_else(|error| Err(RuntimeError::Custom(
                    format!("agent relay: console reader task failed: {error}")
                ))),
                "console reader", true, false,
            ),
            result = &mut *writer => (
                result.unwrap_or_else(|error| Err(RuntimeError::Custom(
                    format!("agent relay: control console writer task failed: {error}")
                ))),
                "control console writer", false, false,
            ),
            Some(result) = bulk.recv() => (result, "bulk console writer", true, true),
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!("agent relay: shutdown signal received");
                    return RelayExit {
                        failure: None,
                        control_writer_usable: false,
                        can_observe_failure_terminals: false,
                    };
                }
                continue;
            }
        };

        let failure = match result {
            Ok(()) if relay_shutdown_requested(shutdown) => None,
            Ok(()) => Some(RuntimeError::Custom(format!(
                "agent relay: {name} stopped unexpectedly"
            ))),
            Err(error) => Some(error),
        };

        return RelayExit {
            failure,
            control_writer_usable,
            can_observe_failure_terminals,
        };
    }
}

/// A signalled or dropped shutdown sender permits clean task completion.
fn relay_shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}

/// Both physical lanes must be writable before admitting another SDK client.
fn input_is_stalled(shared: &ConsoleSharedState, bulk: Option<&ConsoleSharedState>) -> bool {
    *shared.input_stalled.borrow() || bulk.is_some_and(|lane| *lane.input_stalled.borrow())
}

/// Wake a pending client admission without cancelling an already-enqueued frame.
async fn wait_for_input_stall(shared: &ConsoleSharedState, bulk: Option<&ConsoleSharedState>) {
    let mut control = shared.input_stalled.subscribe();
    let mut bulk = bulk.map(|lane| lane.input_stalled.subscribe());

    tokio::select! {
        _ = control.wait_for(|stalled| *stalled) => {}
        _ = async {
            if let Some(bulk) = &mut bulk {
                let _ = bulk.wait_for(|stalled| *stalled).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
    }
}

/// Background task that pushes client frames into the rx_ring for the guest.
/// Retries on full ring with backoff to avoid dropping frames.
async fn ring_writer_task(
    shared: Arc<ConsoleSharedState>,
    mut rx: mpsc::Receiver<ControlWrite>,
) -> RuntimeResult<()> {
    let _lifetime = WorkloadWriterGuard(Arc::clone(&shared.workload_control));
    #[cfg(unix)]
    let capacity_fd = match AsyncFd::new(shared.rx_capacity_wake.as_raw_fd()) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(RuntimeError::Custom(format!(
                "agent relay: failed to watch console capacity: {error}"
            )));
        }
    };

    let workload = &shared.workload_control;
    let mut private = workload.start();
    let mut pending = VecDeque::with_capacity(AGENT_WRITE_CHANNEL_CAPACITY);
    let mut ordinary_closed = false;
    let mut input_stall = None;
    loop {
        let changed = workload.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if shared.is_closed() {
            break;
        }
        if workload.gated() {
            workload.park(false);
        }
        // Moving frames into the bounded scheduler does not release their class admission. A full
        // data class therefore cannot hide another client's metadata in the canonical mailbox.
        while pending.len() < AGENT_WRITE_CHANNEL_CAPACITY && !ordinary_closed {
            match rx.try_recv() {
                Ok(write) => pending.push_back(write),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => ordinary_closed = true,
            }
        }
        let mut wait_clock_capacity = false;
        let write = if let Ok(write) = private.try_recv() {
            Some(ControlWrite::from(write.0))
        } else {
            let (write, wait_capacity) =
                select_control_write(&mut pending, workload, Some(&shared))
                    .map_err(RuntimeError::Custom)?;
            wait_clock_capacity = wait_capacity;
            write
        };
        if !wait_clock_capacity && write.is_none() && !workload.gated() {
            input_stall = None;
        } else if wait_clock_capacity && input_stall.is_none() {
            input_stall = Some(InputStall::new(&shared.input_stalled, INPUT_STALL_TIMEOUT));
        }

        if let Some(stall) = &mut input_stall {
            stall.set_paused(write.is_none() && workload.gated());
        }

        if let Some(write) = write {
            let ControlWrite {
                data,
                completion,
                admission,
                ..
            } = write;
            if !push_bulk_fragment_with_stall(
                &shared,
                data,
                #[cfg(unix)]
                &capacity_fd,
                INPUT_STALL_TIMEOUT,
                &mut input_stall,
            )
            .await
            {
                workload.close();
                return Err(RuntimeError::Custom("agent console writer closed".into()));
            }
            if let Some(completion) = completion {
                let _ = completion.send(());
                shared.rx_capacity_wake.wake();
            }
            drop(admission);
            continue;
        }
        if ordinary_closed && pending.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            write = private.recv() => {
                let Some(write) = write else { break; };
                if !push_bulk_fragment_with_stall(
                    &shared,
                    write.0,
                    #[cfg(unix)]
                    &capacity_fd,
                    INPUT_STALL_TIMEOUT,
                    &mut input_stall,
                ).await {
                    workload.close();
                    return Err(RuntimeError::Custom("private agent console writer closed".into()));
                }
            }
            _ = &mut changed => {}
            _ = async {
                if let Some(stall) = &input_stall {
                    stall.watch().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            available = wait_console_capacity(&shared, #[cfg(unix)] &capacity_fd), if wait_clock_capacity => {
                if !available {
                    return Err(RuntimeError::Custom("agent console capacity watcher closed".into()));
                }
            }
            write = rx.recv(), if pending.len() < AGENT_WRITE_CHANNEL_CAPACITY && !ordinary_closed => {
                if let Some(write) = write {
                    pending.push_back(write);
                } else {
                    ordinary_closed = true;
                }
            }
        }
    }
    workload.close();
    tracing::debug!("agent relay: ring writer task exiting");
    Ok(())
}

/// Keep the common FIFO path constant-time. Only a credit-blocked payload head enables a bounded
/// scan for unrelated metadata or independent TCP return credit. Input/finish order and all
/// cancellation, opening, lease and global fences remain intact.
fn select_control_write(
    pending: &mut VecDeque<ControlWrite>,
    workload: &WorkloadControl,
    shared: Option<&ConsoleSharedState>,
) -> Result<(Option<ControlWrite>, bool), String> {
    let mut wait_capacity = false;
    let Some(head) = pending.front_mut() else {
        return Ok((None, false));
    };
    if admit_control_write(
        head,
        workload,
        shared,
        &mut wait_capacity,
        crate::clock::current_clock_sync_frame,
    )? {
        return Ok((pending.pop_front(), wait_capacity));
    }
    if !head.uses_data_credit || workload.gated() {
        return Ok((None, wait_capacity));
    }
    for index in 1..pending.len() {
        let candidate = &pending[index];
        if candidate.uses_data_credit
            || pending
                .iter()
                .take(index)
                .any(|earlier| earlier.order.conflicts(candidate.order))
        {
            continue;
        }
        if admit_control_write(
            &mut pending[index],
            workload,
            shared,
            &mut wait_capacity,
            crate::clock::current_clock_sync_frame,
        )? {
            return Ok((pending.remove(index), wait_capacity));
        }
    }
    Ok((None, wait_capacity))
}

fn admit_control_write(
    write: &mut ControlWrite,
    workload: &WorkloadControl,
    shared: Option<&ConsoleSharedState>,
    wait_capacity: &mut bool,
    clock_frame: impl FnOnce() -> RuntimeResult<Bytes>,
) -> Result<bool, String> {
    if matches!(write.order, ControlOrder::MaintenanceClock) {
        // No transport credit has been charged yet. Refresh before each capacity attempt, including
        // retries after pause, and charge the actual CBOR length rather than the reserved maximum.
        write.data = clock_frame().map_err(|error| error.to_string())?;
        if let Some(shared) = shared {
            shared.rx_capacity_wake.drain();
            if !shared.rx_ring.can_fit(write.data.len()) {
                *wait_capacity = !workload.gated();
                return Ok(false);
            }
            // This is the sole post-Ready producer. No await separates this successful capacity
            // check, transport admission and the atomic whole-frame queue push, so a clock cannot
            // acquire a timestamp and then sleep waiting for physical queue capacity.
        }
    }
    workload.admit(write.uses_data_credit, write.data.len())
}

async fn wait_console_capacity(
    shared: &Arc<ConsoleSharedState>,
    #[cfg(unix)] capacity_fd: &AsyncFd<i32>,
) -> bool {
    #[cfg(unix)]
    {
        let _ = shared;
        let Ok(mut ready) = capacity_fd.readable().await else {
            return false;
        };
        ready.clear_ready();
        true
    }
    #[cfg(windows)]
    {
        // This select branch is cancelable. A blocking wake waiter would survive cancellation
        // and accumulate across other traffic; only a pending, ring-blocked maintenance clock
        // needs this bounded retry on platforms without the Unix readiness adapter.
        let delay_ms = if *shared.input_stalled.borrow() {
            100
        } else {
            1
        };
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        !shared.is_closed()
    }
}

/// Apply deficit round robin before admitting client raw records to the bulk console ring.
async fn bulk_ring_writer_task(
    shared: Arc<ConsoleSharedState>,
    mut rx: mpsc::Receiver<BulkWriterCommand>,
    workload: Arc<WorkloadControl>,
) -> RuntimeResult<()> {
    let _lifetime = WorkloadWriterGuard(Arc::clone(&workload));
    #[cfg(unix)]
    let capacity_fd = match AsyncFd::new(shared.rx_capacity_wake.as_raw_fd()) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(RuntimeError::Custom(format!(
                "agent relay: failed to watch bulk console capacity: {error}"
            )));
        }
    };
    let mut flows = HashMap::<(ClientIncarnation, u32), BulkWriteFlow>::new();
    let mut active = VecDeque::<(ClientIncarnation, u32)>::new();
    let mut retired = HashMap::<ClientIncarnation, Vec<u64>>::new();

    loop {
        let changed = workload.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if shared.is_closed() {
            break;
        }
        if workload.gated() {
            workload.park(true);
            changed.await;
            continue;
        }
        while let Ok(command) = rx.try_recv() {
            apply_bulk_writer_command(command, &mut flows, &mut active, &mut retired)?;
        }
        let mut progressed = false;
        let mut needs_deficit_round = false;
        if !active.is_empty() {
            let round_len = active.len();
            // DRR fairness is irrelevant when only one flow is runnable. Grant the full bounded
            // burst in that case so a 256 KiB default record does not force one executor yield per
            // record. Once a competitor appears, return to the normal per-flow quantum.
            let quantum = if round_len == 1 {
                BULK_WRITE_MAX_BURST
            } else {
                BULK_WRITE_QUANTUM
            };
            for _ in 0..round_len {
                let key = active.pop_front().expect("active bulk flow exists");
                if let Some(flow) = flows.get_mut(&key) {
                    flow.deficit = flow
                        .deficit
                        .saturating_add(quantum)
                        .min(BULK_WRITE_MAX_BURST);
                }

                let mut burst = 0usize;
                loop {
                    let next_len = flows
                        .get(&key)
                        .and_then(|flow| flow.queue.front())
                        .map(|write| write.payload_len)
                        .unwrap_or(0);
                    let can_send = flows.get(&key).is_some_and(|flow| {
                        next_len != 0
                            && next_len <= flow.deficit
                            && burst.saturating_add(next_len) <= BULK_WRITE_MAX_BURST
                    });
                    if !can_send {
                        needs_deficit_round |=
                            flows.get(&key).is_some_and(|flow| next_len > flow.deficit);
                        break;
                    }
                    let wire_len = CLIENT_INCARNATION_SIZE
                        + LEN_PREFIX_SIZE
                        + FRAME_HEADER_SIZE
                        + BULK_HEADER_SIZE
                        + next_len;
                    if !workload
                        .admit(true, wire_len)
                        .map_err(RuntimeError::Custom)?
                    {
                        break;
                    }

                    let write = {
                        let flow = flows.get_mut(&key).expect("scheduled bulk flow exists");
                        let write = flow.queue.pop_front().expect("scheduled bulk frame exists");
                        flow.queued_bytes = flow.queued_bytes.saturating_sub(next_len);
                        flow.deficit = flow.deficit.saturating_sub(next_len);
                        write
                    };
                    if !push_bulk_write(
                        &shared,
                        write,
                        #[cfg(unix)]
                        &capacity_fd,
                    )
                    .await
                    {
                        return Err(RuntimeError::Custom(
                            "agent relay: bulk console writer closed".into(),
                        ));
                    }
                    burst = burst.saturating_add(next_len);
                    progressed = true;
                }

                if flows.get(&key).is_some_and(|flow| flow.queue.is_empty()) {
                    flows.remove(&key);
                } else {
                    active.push_back(key);
                }
            }
        }
        if progressed || needs_deficit_round {
            tokio::task::yield_now().await;
        } else {
            tokio::select! {
                _ = &mut changed => {}
                command = rx.recv() => {
                    let Some(command) = command else { break; };
                    apply_bulk_writer_command(command, &mut flows, &mut active, &mut retired)?;
                }
            }
        }
    }
    Ok(())
}

fn apply_bulk_writer_command(
    command: BulkWriterCommand,
    flows: &mut HashMap<(ClientIncarnation, u32), BulkWriteFlow>,
    active: &mut VecDeque<(ClientIncarnation, u32)>,
    retired: &mut HashMap<ClientIncarnation, Vec<u64>>,
) -> RuntimeResult<()> {
    match command {
        BulkWriterCommand::Write(write) => enqueue_bulk_write(write, flows, active, retired),
        BulkWriterCommand::DropFlow {
            incarnation,
            id,
            completion,
        } => {
            let key = (incarnation, id);
            flows.remove(&key);
            active.retain(|active_key| *active_key != key);
            retire_relay_correlation(retired, incarnation, id)?;
            let _ = completion.send(());
            Ok(())
        }
        BulkWriterCommand::DropIncarnation {
            incarnation,
            completion,
        } => {
            flows.retain(|(owner, _), _| *owner != incarnation);
            active.retain(|(owner, _)| *owner != incarnation);
            retired.remove(&incarnation);
            let _ = completion.send(());
            Ok(())
        }
    }
}

fn enqueue_bulk_write(
    write: BulkWrite,
    flows: &mut HashMap<(ClientIncarnation, u32), BulkWriteFlow>,
    active: &mut VecDeque<(ClientIncarnation, u32)>,
    retired: &HashMap<ClientIncarnation, Vec<u64>>,
) -> RuntimeResult<()> {
    let flow = write.flow;
    let payload_len = write.payload_len;
    if flow != BulkFlow::HostToGuest {
        return Err(RuntimeError::Custom(
            "host bulk scheduler received a guest-to-host record".into(),
        ));
    }
    if write.id == 0 {
        return Err(RuntimeError::Custom(
            "bulk record cannot use correlation ID zero".into(),
        ));
    }
    let key = (write.incarnation, write.id);
    if relay_correlation_is_retired(retired, write.incarnation, write.id) {
        // Cross-sender cancellation may overtake a write already in flight to this actor. The
        // tombstone consumes that bounded late record without recreating scheduler state.
        return Ok(());
    }
    if !flows.contains_key(&key) {
        let client_flows = flows
            .keys()
            .filter(|(incarnation, _)| *incarnation == write.incarnation)
            .count();
        if client_flows >= BULK_WRITE_MAX_FLOWS_PER_CLIENT {
            return Err(RuntimeError::Custom(format!(
                "relay client exceeded active bulk-flow limit for correlation {}",
                write.id
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

    let flow = flows.get_mut(&key).expect("new bulk flow exists");
    let queued_bytes = flow
        .queued_bytes
        .checked_add(payload_len)
        .ok_or_else(|| RuntimeError::Custom("bulk flow byte budget overflow".into()))?;
    if queued_bytes > BULK_WRITE_FLOW_CAPACITY {
        return Err(RuntimeError::Custom(format!(
            "bulk flow {} exceeded queued byte budget",
            write.id
        )));
    }
    flow.queued_bytes = queued_bytes;
    flow.queue.push_back(write);
    Ok(())
}

/// Validate the fixed outer and generation-8 bulk headers without copying the payload.
fn bulk_wire_metadata(data: &Bytes) -> RuntimeResult<(BulkKind, BulkFlow, u64, usize)> {
    let minimum_len = LEN_PREFIX_SIZE + FRAME_HEADER_SIZE + BULK_HEADER_SIZE + 1;
    if data.len() < minimum_len {
        return Err(RuntimeError::Custom(
            "bulk frame is missing its raw payload".into(),
        ));
    }

    let frame_len = u32::from_be_bytes(data[..LEN_PREFIX_SIZE].try_into().unwrap()) as usize;
    if frame_len != data.len() - LEN_PREFIX_SIZE || frame_len > MAX_FRAME_SIZE as usize {
        return Err(RuntimeError::Custom(
            "bulk frame length prefix does not match its wire length".into(),
        ));
    }
    if data[8] != FLAG_BULK {
        return Err(RuntimeError::Custom(
            "bulk frame must use the exclusive bulk flag".into(),
        ));
    }

    let kind = BulkKind::from_wire(data[9])
        .ok_or_else(|| RuntimeError::Custom(format!("unknown bulk kind {}", data[9])))?;
    let flow = BulkFlow::from_wire(data[10])
        .ok_or_else(|| RuntimeError::Custom(format!("unknown bulk flow {}", data[10])))?;
    if data[11] != 0 || data[12] != 0 {
        return Err(RuntimeError::Custom(
            "reserved bulk header bytes must be zero".into(),
        ));
    }

    let offset = u64::from_be_bytes(data[13..21].try_into().unwrap());
    let payload_len = data
        .len()
        .checked_sub(LEN_PREFIX_SIZE + FRAME_HEADER_SIZE + BULK_HEADER_SIZE)
        .expect("minimum bulk wire length was validated");
    if payload_len > MAX_BULK_RECORD_PAYLOAD as usize {
        return Err(RuntimeError::Custom(format!(
            "bulk record payload {payload_len} exceeds protocol maximum {MAX_BULK_RECORD_PAYLOAD}"
        )));
    }
    offset
        .checked_add(payload_len as u64)
        .ok_or_else(|| RuntimeError::Custom("bulk record end offset overflows u64".into()))?;

    Ok((kind, flow, offset, payload_len))
}

async fn push_bulk_write(
    shared: &Arc<ConsoleSharedState>,
    write: BulkWrite,
    #[cfg(unix)] capacity_fd: &AsyncFd<i32>,
) -> bool {
    // Keep the incarnation outside the unchanged generation-8 frame. Two queue fragments avoid
    // copying the potentially megabyte-sized opaque payload merely to prepend sixteen bytes.
    let prefix = Bytes::copy_from_slice(&write.incarnation);
    if !push_bulk_fragment(
        shared,
        prefix,
        #[cfg(unix)]
        capacity_fd,
    )
    .await
    {
        return false;
    }
    match write.data {
        BulkWriteData::Inline(data) => {
            push_bulk_fragment(
                shared,
                data,
                #[cfg(unix)]
                capacity_fd,
            )
            .await
        }
        #[cfg(unix)]
        BulkWriteData::Shared { header, payload } => {
            if !push_bulk_fragment(shared, header, capacity_fd).await {
                return false;
            }
            push_bulk_fragment(shared, payload, capacity_fd).await
        }
    }
}

async fn push_bulk_fragment(
    shared: &Arc<ConsoleSharedState>,
    data: Bytes,
    #[cfg(unix)] capacity_fd: &AsyncFd<i32>,
) -> bool {
    push_bulk_fragment_with_timeout(
        shared,
        data,
        #[cfg(unix)]
        capacity_fd,
        INPUT_STALL_TIMEOUT,
    )
    .await
}

async fn push_bulk_fragment_with_timeout(
    shared: &Arc<ConsoleSharedState>,
    data: Bytes,
    #[cfg(unix)] capacity_fd: &AsyncFd<i32>,
    timeout: std::time::Duration,
) -> bool {
    let mut stall = None;
    push_bulk_fragment_with_stall(
        shared,
        data,
        #[cfg(unix)]
        capacity_fd,
        timeout,
        &mut stall,
    )
    .await
}

/// Carry a scheduler capacity wait into delivery without resetting its deadline or health.
async fn push_bulk_fragment_with_stall<'a>(
    shared: &'a Arc<ConsoleSharedState>,
    mut data: Bytes,
    #[cfg(unix)] capacity_fd: &AsyncFd<i32>,
    timeout: std::time::Duration,
    stall: &mut Option<InputStall<'a>>,
) -> bool {
    // Private lifecycle traffic remains deliverable while ordinary input is gated.
    // Once a write is selected, capacity waiting is real backpressure again.
    if let Some(stall) = stall.as_mut() {
        stall.set_paused(false);
    }

    loop {
        match shared.rx_ring.push(data) {
            Ok(()) => {
                shared.rx_wake.wake();
                *stall = None;
                return true;
            }
            Err(returned) => {
                data = returned;
                if shared.is_closed() {
                    return false;
                }
                shared.rx_capacity_wake.drain();
                if shared.rx_ring.can_fit(data.len()) {
                    continue;
                }

                let stall =
                    stall.get_or_insert_with(|| InputStall::new(&shared.input_stalled, timeout));

                tokio::select! {
                    available = async {
                        #[cfg(unix)]
                        { wait_console_capacity(shared, capacity_fd).await }
                        #[cfg(windows)]
                        {
                            let shared = Arc::clone(shared);
                            tokio::task::spawn_blocking(move || {
                                shared.rx_capacity_wake.wait_timeout(std::time::Duration::from_secs(60));
                                !shared.is_closed()
                            }).await.unwrap_or(false)
                        }
                    } => {
                        if !available {
                            return false;
                        }
                    }
                    _ = stall.watch() => {}
                }
            }
        }
    }
}

/// Background task that reads frames from the tx_ring (written by the guest
/// agent) and routes them to the correct client based on correlation ID range.
///
/// When `log_writer` is `Some`, the task also taps the primary session's
/// `ExecStdout` / `ExecStderr` payloads into `exec.log`. The "primary"
/// session is the first one whose `ExecRequest` arrives after the relay
/// starts, recorded via CAS into `primary_session_id`. See
/// `design/runtime/sandbox-logs.md` D3a.
async fn ring_reader_task(
    shared: Arc<ConsoleSharedState>,
    bulk_shared: Option<Arc<ConsoleSharedState>>,
    range_lease_active: bool,
    mut command_rx: mpsc::Receiver<MergeCommand>,
    context: RingReaderContext,
) -> RuntimeResult<()> {
    let RingReaderContext {
        initial,
        clients,
        log_writer,
        session_registry,
        pending_disconnects,
        bulk_writer,
    } = context;
    if bulk_shared.is_none() {
        // Combined mode has one inherently ordered physical stream, so it needs neither a lane
        // actor nor a cross-lane merger. Reading and routing it directly preserves the PR2 hot
        // path while dual-port keeps the isolation machinery below.
        return combined_ring_reader_task(
            initial.control,
            shared,
            range_lease_active,
            clients,
            log_writer,
            session_registry,
            pending_disconnects,
        )
        .await;
    }
    let dual_port = bulk_shared.is_some();
    let workload = Arc::clone(&shared.workload_control);
    let control_workload = Arc::clone(&workload);
    let control_lane_budget = Arc::new(Semaphore::new(if dual_port {
        CONTROL_LANE_OUTPUT_BYTE_CAPACITY
    } else {
        CLIENT_OUTPUT_BYTE_CAPACITY
    }));
    let bulk_lane_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_BYTE_CAPACITY));
    let (control_lane_tx, mut control_lane_rx) = mpsc::channel::<LaneEvent>(128);
    let (bulk_lane_tx, mut bulk_lane_rx) = mpsc::channel::<LaneEvent>(128);
    let (lane_failure_tx, mut lane_failure_rx) = mpsc::channel(2);
    let control_failure_tx = lane_failure_tx.clone();
    let control_handle = tokio::spawn(async move {
        let result = lane_reader_task(
            initial.control,
            shared,
            GuestLane::Control,
            dual_port,
            range_lease_active,
            control_lane_tx,
            control_lane_budget,
            control_workload,
        )
        .await;
        let _ = control_failure_tx.send((GuestLane::Control, result)).await;
    });
    let bulk_handle = bulk_shared.map(|shared| {
        tokio::spawn(async move {
            let result = lane_reader_task(
                initial.bulk,
                shared,
                GuestLane::Bulk,
                true,
                range_lease_active,
                bulk_lane_tx,
                bulk_lane_budget,
                workload,
            )
            .await;
            let _ = lane_failure_tx.send((GuestLane::Bulk, result)).await;
        })
    });
    let mut merger = GuestFrameMerger::default();

    let outcome = 'reader: loop {
        let lane_event = tokio::select! {
            biased;
            event = control_lane_rx.recv() => {
                let Some(event) = event else {
                    break 'reader Err(RuntimeError::Custom(
                        "agent relay: control console lane reader stopped".into(),
                    ));
                };
                event
            }
            failure = lane_failure_rx.recv() => {
                let Some((lane, result)) = failure else {
                    break 'reader Err(RuntimeError::Custom(
                        "agent relay: console lane failure monitor stopped".into(),
                    ));
                };
                let detail = match result {
                    Ok(()) => "stopped unexpectedly".to_string(),
                    Err(error) => error.to_string(),
                };
                break 'reader Err(RuntimeError::Custom(format!(
                    "agent relay: {lane:?} lane failed: {detail}"
                )));
            }
            command = command_rx.recv() => {
                let Some(command) = command else { continue; };
                match command {
                    MergeCommand::Register { incarnation, id, completion } => {
                        let _ = completion.send(merger.register(incarnation, id));
                        continue;
                    }
                    MergeCommand::DropFlow { incarnation, id, completion } => {
                        merger.drop_flow(incarnation, id);
                        let _ = completion.send(());
                        continue;
                    }
                    MergeCommand::DropIncarnation { incarnation, completion } => {
                        merger.drop_incarnation(incarnation);
                        let _ = completion.send(());
                        continue;
                    }
                }
            }
            event = bulk_lane_rx.recv(), if dual_port => {
                let Some(event) = event else {
                    break 'reader Err(RuntimeError::Custom(
                        "agent relay: bulk console lane reader stopped".into(),
                    ));
                };
                event
            }
        };

        let mut lane_frame = match lane_event {
            LaneEvent::Frame(frame) => frame,
            LaneEvent::DisconnectAck(ack) => {
                complete_relay_client_disconnect(&pending_disconnects, ack).await?;
                continue;
            }
        };

        // A dedicated-lane prefix is authoritative only when it matches the client currently
        // owning the correlation range. Control frames inherit that same owner before merging so
        // held state can never cross a slot-reuse boundary.
        if dual_port {
            let Some(client_slot) = relay_client_slot(lane_frame.frame.id) else {
                break 'reader Err(RuntimeError::Custom(format!(
                    "agent relay: guest frame uses unassigned correlation ID {}",
                    lane_frame.frame.id
                )));
            };
            let (current_incarnation, claimed_is_live) = {
                let clients = clients.lock().await;
                let current = clients
                    .get(&client_slot)
                    .and_then(|client| client.incarnation);
                let claimed_is_live = lane_frame.incarnation.is_some_and(|claimed| {
                    clients
                        .values()
                        .any(|client| client.incarnation == Some(claimed))
                });
                (current, claimed_is_live)
            };
            let Some(current_incarnation) = current_incarnation else {
                tracing::debug!(
                    id = lane_frame.frame.id,
                    "agent relay: dropping frame for an unowned client range"
                );
                continue;
            };
            if lane_frame
                .incarnation
                .is_some_and(|claimed| claimed != current_incarnation)
            {
                if claimed_is_live {
                    break 'reader Err(RuntimeError::Custom(format!(
                        "agent relay: dedicated bulk correlation {} lies outside its client incarnation range",
                        lane_frame.frame.id
                    )));
                }
                tracing::debug!(
                    id = lane_frame.frame.id,
                    "agent relay: dropping stale dedicated-lane incarnation"
                );
                continue;
            }
            lane_frame.incarnation = Some(current_incarnation);
        }

        // A guest-originated cancellation must cut the host-to-guest scheduler before the SDK
        // observes it. Otherwise bytes already retained by that scheduler could arrive after
        // agentd has torn down the destination operation.
        if dual_port
            && lane_frame.frame.flags == MessageType::BulkCancel.flags()
            && decode_frame(lane_frame.frame.data.as_ref())
                .is_ok_and(|message| message.t == MessageType::BulkCancel)
        {
            let incarnation = lane_frame
                .incarnation
                .expect("dual-port control frame inherited its current owner");
            let bulk_writer = bulk_writer
                .as_ref()
                .expect("dual-port reader has a bulk scheduler");
            let (completion, completed) = oneshot::channel();
            bulk_writer
                .send(BulkWriterCommand::DropFlow {
                    incarnation,
                    id: lane_frame.frame.id,
                    completion,
                })
                .await
                .map_err(|_| RuntimeError::Custom("bulk scheduler stopped during cancel".into()))?;
            completed.await.map_err(|_| {
                RuntimeError::Custom("bulk scheduler dropped cancellation completion".into())
            })?;
        }
        let frames = if dual_port {
            match merger.push(lane_frame) {
                Ok(frames) => frames,
                Err(error) => {
                    break 'reader Err(RuntimeError::Custom(format!(
                        "agent relay: cross-lane merge failed: {error}"
                    )));
                }
            }
        } else {
            vec![lane_frame]
        };

        for lane_frame in frames {
            if let Err(error) = route_guest_lane_frame(
                lane_frame,
                dual_port,
                &clients,
                log_writer.as_deref(),
                &session_registry,
            )
            .await
            {
                break 'reader Err(error);
            }
        }
    };

    control_handle.abort();
    if let Some(handle) = bulk_handle {
        handle.abort();
    }
    outcome
}

/// Route one admitted guest frame without awaiting the destination SDK socket.
async fn route_guest_lane_frame(
    lane_frame: LaneFrame,
    dual_port: bool,
    clients: &Arc<Mutex<HashMap<u32, ClientState>>>,
    log_writer: Option<&LogWriter>,
    session_registry: &SessionRegistry,
) -> RuntimeResult<()> {
    let LaneFrame {
        frame,
        incarnation,
        _permit: lane_permit,
    } = lane_frame;
    if !has_valid_frame_flags(frame.flags) {
        return Err(RuntimeError::Custom(format!(
            "agent relay: guest frame id={} has invalid flags {}",
            frame.id, frame.flags
        )));
    }
    let Some(client_slot) = relay_client_slot(frame.id) else {
        return Err(RuntimeError::Custom(format!(
            "agent relay: guest frame uses unassigned correlation ID {}",
            frame.id
        )));
    };
    let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;

    // Clone only nonblocking routing handles while holding the shared owner map.
    let writer_result = {
        let mut map = clients.lock().await;
        if let Some(client) = map.get_mut(&client_slot)
            && (!dual_port || client.incarnation == incarnation)
        {
            if is_terminal {
                client.active_sessions.remove(&frame.id);
                client.active_bulk.lock().unwrap().remove(&frame.id);
            }
            Ok(ClientRoute {
                write_tx: client.write_tx.clone(),
                write_budget: Arc::clone(&client.write_budget),
                disconnect_tx: client.disconnect_tx.clone(),
                #[cfg(unix)]
                local_outbound: client.local_outbound.clone(),
            })
        } else {
            Err(frame.id)
        }
    };

    // Incarnation-bearing output must not reach logs after its owner has changed. Combined mode
    // retains the historical behavior of capturing terminal output after SDK disconnect.
    if (!dual_port || writer_result.is_ok())
        && frame.flags != FLAG_BULK
        && let Some(writer) = log_writer
    {
        tap_frame_into_log(&frame, writer, session_registry);
    }

    match writer_result {
        Ok(route) => {
            let charged = frame.data.len().saturating_add(OUTPUT_BUDGET_GRANULE - 1)
                / OUTPUT_BUDGET_GRANULE
                * OUTPUT_BUDGET_GRANULE;
            let Ok(charged) = u32::try_from(charged) else {
                return Err(RuntimeError::Custom(
                    "agent relay: client frame budget overflow".into(),
                ));
            };
            let client_permit = route
                .write_budget
                .try_acquire_many_owned(charged)
                .map_err(|_| {
                RuntimeError::Custom(format!(
                    "agent relay: per-client output budget invariant failed for slot {client_slot}"
                ))
            })?;

            // The shared arena is a local optimization only. If all fitting slots are leased,
            // preserve forward progress by sending this record through the original socket path.
            // Any error other than temporary capacity means the negotiated local transport is
            // corrupt and must fail closed instead of silently changing its interpretation.
            #[cfg(unix)]
            if frame.flags == FLAG_BULK
                && let Some(producer) = route.local_outbound
            {
                let (kind, flow, offset, payload_len) = bulk_wire_metadata(&frame.data)?;
                let payload_start = LEN_PREFIX_SIZE + FRAME_HEADER_SIZE + BULK_HEADER_SIZE;
                let record = BulkRecord {
                    id: frame.id,
                    kind,
                    flow,
                    offset,
                    payload: frame.data.slice(payload_start..payload_start + payload_len),
                };
                match producer.try_prepare(&record) {
                    Ok(prepared) => {
                        if let Err(error) = route.write_tx.send(ClientWrite {
                            data: ClientWriteData::LocalBulk(prepared),
                            _lane_permit: Some(lane_permit),
                            _client_permit: client_permit,
                        }) {
                            tracing::warn!(
                                %error,
                                "agent relay: disconnecting slot={client_slot}; local client writer stopped"
                            );
                            let _ = route.disconnect_tx.send(true);
                        }
                        return Ok(());
                    }
                    Err(LocalShmError::Full(_)) => {}
                    Err(error) => {
                        return Err(RuntimeError::Custom(format!(
                            "agent relay: local shared-arena output failed: {error}"
                        )));
                    }
                }
            }

            if let Err(error) = route.write_tx.send(ClientWrite {
                data: ClientWriteData::Inline(frame.data),
                _lane_permit: Some(lane_permit),
                _client_permit: client_permit,
            }) {
                tracing::warn!(
                    %error,
                    "agent relay: disconnecting slot={client_slot}; client writer stopped"
                );
                let _ = route.disconnect_tx.send(true);
            }
        }
        Err(id) => {
            tracing::debug!(
                "agent relay: no client for slot={client_slot} id={id} (frame dropped)"
            );
        }
    }
    Ok(())
}

/// Private lifecycle replies bypass SDK output budgets, but never skip a framing boundary.
fn handle_workload_frame(
    workload: &WorkloadControl,
    frame: &RawFrame,
    remaining: usize,
) -> RuntimeResult<()> {
    let message = decode_frame(&frame.data)?;
    if remaining != 0
        && workload
            .requires_frozen_boundary(&message)
            .map_err(RuntimeError::Custom)?
    {
        return Err(RuntimeError::Custom(
            "frozen primary transport has a trailing frame or partial prefix".into(),
        ));
    }
    workload.reply(message).map_err(RuntimeError::Custom)
}

/// Read and route the single ordered guest stream without dual-port actor hops.
async fn combined_ring_reader_task(
    mut buf: BytesMut,
    shared: Arc<ConsoleSharedState>,
    range_lease_active: bool,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    log_writer: Option<Arc<LogWriter>>,
    session_registry: Arc<SessionRegistry>,
    pending_disconnects: Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
) -> RuntimeResult<()> {
    #[cfg(unix)]
    let async_fd = AsyncFd::new(shared.tx_wake.as_raw_fd()).map_err(RuntimeError::Io)?;
    let output_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_BYTE_CAPACITY));
    if !buf.is_empty() {
        shared.tx_wake.wake();
    }

    loop {
        #[cfg(unix)]
        {
            let mut guard = async_fd.readable().await.map_err(RuntimeError::Io)?;
            guard.clear_ready();
        }
        #[cfg(windows)]
        {
            let shared_for_wait = Arc::clone(&shared);
            let woke = tokio::task::spawn_blocking(move || {
                shared_for_wait
                    .tx_wake
                    .wait_timeout(std::time::Duration::from_millis(100))
            })
            .await
            .unwrap_or(false);
            if !woke {
                continue;
            }
        }

        shared.tx_wake.drain();
        while let Some(chunk) = shared.tx_ring.pop() {
            buf.extend_from_slice(&chunk);
            drop(chunk);
            shared.tx_capacity_wake.wake();
        }

        loop {
            if range_lease_active {
                match try_decode_relay_client_disconnected_ack_from_bytes(&mut buf) {
                    Ok(Some(ack)) => {
                        complete_relay_client_disconnect(&pending_disconnects, ack).await?;
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        shared.close();
                        return Err(RuntimeError::Custom(format!(
                            "decode relay client disconnect acknowledgement: {error}"
                        )));
                    }
                }
            }

            let Some(frame) = try_extract_frame(&mut buf)? else {
                break;
            };
            if frame.id == WORKLOAD_CONTROL_ID {
                handle_workload_frame(&shared.workload_control, &frame, buf.len())?;
                continue;
            }
            let charged = frame.data.len().saturating_add(OUTPUT_BUDGET_GRANULE - 1)
                / OUTPUT_BUDGET_GRANULE
                * OUTPUT_BUDGET_GRANULE;
            let charged = u32::try_from(charged).map_err(|_| {
                RuntimeError::Custom("agent relay: lane frame budget overflow".into())
            })?;
            let lane_permit = Arc::clone(&output_budget)
                .acquire_many_owned(charged)
                .await
                .map_err(|_| RuntimeError::Custom("agent relay: lane budget closed".into()))?;
            route_guest_lane_frame(
                LaneFrame {
                    frame,
                    incarnation: None,
                    _permit: lane_permit,
                },
                false,
                &clients,
                log_writer.as_deref(),
                &session_registry,
            )
            .await?;
        }
    }
}

/// Read and frame one physical guest console lane without interpreting control payloads.
#[allow(clippy::too_many_arguments)]
async fn lane_reader_task(
    mut buf: BytesMut,
    shared: Arc<ConsoleSharedState>,
    lane: GuestLane,
    dual_port: bool,
    range_lease_active: bool,
    event_tx: mpsc::Sender<LaneEvent>,
    budget: Arc<Semaphore>,
    workload: Arc<WorkloadControl>,
) -> RuntimeResult<()> {
    #[cfg(unix)]
    let async_fd = AsyncFd::new(shared.tx_wake.as_raw_fd()).map_err(RuntimeError::Io)?;
    if !buf.is_empty() {
        shared.tx_wake.wake();
    }

    loop {
        #[cfg(unix)]
        {
            let mut guard = async_fd.readable().await.map_err(RuntimeError::Io)?;
            guard.clear_ready();
        }
        #[cfg(windows)]
        {
            let shared_for_wait = Arc::clone(&shared);
            let woke = tokio::task::spawn_blocking(move || {
                shared_for_wait
                    .tx_wake
                    .wait_timeout(std::time::Duration::from_millis(100))
            })
            .await
            .unwrap_or(false);
            if !woke {
                continue;
            }
        }

        shared.tx_wake.drain();
        while let Some(chunk) = shared.tx_ring.pop() {
            buf.extend_from_slice(&chunk);
            drop(chunk);
            shared.tx_capacity_wake.wake();
        }

        if lane == GuestLane::Bulk {
            workload
                .observed_bulk(0, buf.len())
                .map_err(RuntimeError::Custom)?;
        }

        loop {
            if lane == GuestLane::Control && range_lease_active {
                match try_decode_relay_client_disconnected_ack_from_bytes(&mut buf) {
                    Ok(Some(ack)) => {
                        if event_tx.send(LaneEvent::DisconnectAck(ack)).await.is_err() {
                            return Ok(());
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        shared.close();
                        return Err(RuntimeError::Custom(format!(
                            "decode relay client disconnect acknowledgement: {error}"
                        )));
                    }
                }
            }
            let (frame, incarnation) = match lane {
                GuestLane::Control => {
                    let Some(frame) = try_extract_frame(&mut buf)? else {
                        break;
                    };
                    (frame, None)
                }
                GuestLane::Bulk => {
                    let decoded = match try_decode_incarnated_bulk_from_bytes(&mut buf) {
                        Ok(Some(decoded)) => decoded,
                        Ok(None) => break,
                        Err(error) => {
                            shared.close();
                            return Err(RuntimeError::Custom(format!(
                                "decode incarnation-bearing bulk frame: {error}"
                            )));
                        }
                    };
                    (
                        RawFrame {
                            data: decoded.frame,
                            id: decoded.record.id,
                            flags: FLAG_BULK,
                        },
                        Some(decoded.incarnation),
                    )
                }
            };
            let valid_lane = match lane {
                GuestLane::Control => !dual_port || frame.flags != FLAG_BULK,
                GuestLane::Bulk => frame.flags == FLAG_BULK,
            };
            if !valid_lane {
                shared.close();
                return Err(RuntimeError::Custom(format!(
                    "frame id={} flags={} arrived on the wrong physical lane",
                    frame.id, frame.flags
                )));
            }
            if lane == GuestLane::Bulk {
                workload
                    .observed_bulk(CLIENT_INCARNATION_SIZE + frame.data.len(), buf.len())
                    .map_err(RuntimeError::Custom)?;
            } else if frame.id == WORKLOAD_CONTROL_ID {
                handle_workload_frame(&workload, &frame, buf.len())?;
                continue;
            }
            let charged = frame.data.len().saturating_add(OUTPUT_BUDGET_GRANULE - 1)
                / OUTPUT_BUDGET_GRANULE
                * OUTPUT_BUDGET_GRANULE;
            let charged = u32::try_from(charged).map_err(|_| {
                RuntimeError::Custom("agent relay: lane frame budget overflow".into())
            })?;
            let permit = Arc::clone(&budget)
                .acquire_many_owned(charged)
                .await
                .map_err(|_| RuntimeError::Custom("agent relay: lane budget closed".into()))?;
            if event_tx
                .send(LaneEvent::Frame(LaneFrame {
                    frame,
                    incarnation,
                    _permit: permit,
                }))
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    }
}

/// Read a single raw frame from an async reader (used for client connections).
async fn read_raw_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> RuntimeResult<RawFrame> {
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; LEN_PREFIX_SIZE];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(RuntimeError::Custom("agent relay: unexpected EOF".into()));
        }
        Err(e) => return Err(RuntimeError::Io(e)),
    }

    let frame_len = u32::from_be_bytes(len_buf);

    if frame_len > MAX_FRAME_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too large: {frame_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let frame_len = frame_len as usize;

    if frame_len < FRAME_HEADER_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too short: {frame_len} bytes"
        )));
    }

    // Single allocation: length prefix + payload in one Vec.
    let mut data = Vec::with_capacity(LEN_PREFIX_SIZE + frame_len);
    data.extend_from_slice(&len_buf);
    data.resize(LEN_PREFIX_SIZE + frame_len, 0);
    reader.read_exact(&mut data[LEN_PREFIX_SIZE..]).await?;

    let id = u32::from_be_bytes([
        data[LEN_PREFIX_SIZE],
        data[LEN_PREFIX_SIZE + 1],
        data[LEN_PREFIX_SIZE + 2],
        data[LEN_PREFIX_SIZE + 3],
    ]);
    let flags = data[LEN_PREFIX_SIZE + 4];

    Ok(RawFrame {
        data: Bytes::from(data),
        id,
        flags,
    })
}

fn admit_bulk_open(
    active_bulk: &std::sync::Mutex<HashMap<u32, BulkKind>>,
    id: u32,
    kind: BulkKind,
) -> BulkOpenAdmission {
    let mut active = active_bulk.lock().unwrap();
    if active.contains_key(&id) {
        return BulkOpenAdmission::Duplicate;
    }
    if active.len() >= BULK_WRITE_MAX_FLOWS_PER_CLIENT {
        return BulkOpenAdmission::LimitReached;
    }
    active.insert(id, kind);
    BulkOpenAdmission::Accepted
}

fn queue_bulk_open_rejection(
    write_tx: &mpsc::UnboundedSender<ClientWrite>,
    write_budget: &Arc<Semaphore>,
    version: u8,
    id: u32,
    kind: BulkKind,
) -> RuntimeResult<()> {
    let error = format!(
        "client already has the maximum of {BULK_WRITE_MAX_FLOWS_PER_CLIENT} active bulk operations"
    );
    let mut message = match kind {
        BulkKind::Filesystem => Message::with_payload(
            MessageType::FsResponse,
            id,
            &FsResponse {
                ok: false,
                error: Some(error),
                data: None,
            },
        ),
        BulkKind::Tcp => Message::with_payload(MessageType::TcpFailed, id, &TcpFailed { error }),
    }
    .map_err(|error| RuntimeError::Custom(format!("encode bulk admission rejection: {error}")))?;
    // Match the initiating request so an older compatible SDK can decode the terminal response.
    message.v = version;
    queue_client_rejection(write_tx, write_budget, &message)
}

/// Host-side rejection uses the same bounded mailbox as guest responses.
fn queue_client_rejection(
    write_tx: &mpsc::UnboundedSender<ClientWrite>,
    write_budget: &Arc<Semaphore>,
    message: &Message,
) -> RuntimeResult<()> {
    let mut wire = Vec::new();
    codec::encode_to_buf(message, &mut wire).map_err(|error| {
        RuntimeError::Custom(format!("encode bulk admission rejection frame: {error}"))
    })?;
    let charged = wire
        .len()
        .div_ceil(OUTPUT_BUDGET_GRANULE)
        .saturating_mul(OUTPUT_BUDGET_GRANULE);
    let charged = u32::try_from(charged)
        .map_err(|_| RuntimeError::Custom("bulk admission rejection budget overflow".into()))?;
    let client_permit = Arc::clone(write_budget)
        .try_acquire_many_owned(charged)
        .map_err(|_| {
            RuntimeError::Custom("client output full while rejecting a bulk operation".into())
        })?;
    write_tx
        .send(ClientWrite {
            data: ClientWriteData::Inline(Bytes::from(wire)),
            _lane_permit: None,
            _client_permit: client_permit,
        })
        .map_err(|_| RuntimeError::Custom("client writer stopped during bulk rejection".into()))
}

/// Background task that reads frames from a client and forwards them to the
/// ring writer channel. Handles client disconnect with session cleanup.
///
/// The argument count is over the clippy default (7) because the task
/// shares per-relay state across both tasks: client routing
/// (`agent_tx`, `clients`, `used_slots`, `drain_tx`) plus the
/// session registry / monotonic id atomic for the log capture path.
/// Bundling them into a struct would be more boilerplate than the
/// lint guards against — there's a single call site.
#[allow(clippy::too_many_arguments)]
async fn client_reader_task(
    slot: u32,
    mut reader: impl AsyncRead + Unpin + Send + 'static,
    agent_tx: ControlWriter,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    used_slots: Arc<Mutex<HashSet<u32>>>,
    drain_tx: mpsc::Sender<()>,
    session_registry: Arc<SessionRegistry>,
    next_session_id: Arc<AtomicU64>,
    bulk_tx: Option<mpsc::Sender<BulkWriterCommand>>,
    bulk_budget: Option<Arc<Semaphore>>,
    merge_command_tx: mpsc::Sender<MergeCommand>,
    pending_disconnects: Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
    id_start: u32,
    id_end_exclusive: u32,
    incarnation: Option<ClientIncarnation>,
    active_bulk: Arc<std::sync::Mutex<HashMap<u32, BulkKind>>>,
    write_tx: mpsc::UnboundedSender<ClientWrite>,
    write_budget: Arc<Semaphore>,
    mut disconnect_rx: watch::Receiver<bool>,
    resident_paused: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(unix)] local_write_tx: mpsc::UnboundedSender<LocalClientWrite>,
) {
    #[cfg(unix)]
    let (local_release_tx, mut local_release_rx) = mpsc::unbounded_channel();
    #[cfg(unix)]
    let mut local_server: Option<Arc<LocalShmServer>> = None;
    #[cfg(unix)]
    let mut ordinary_frame_seen = false;

    loop {
        #[cfg(unix)]
        let mut frame = tokio::select! {
            result = read_raw_frame(&mut reader) => match result {
                Ok(frame) => frame,
                Err(error) => {
                    tracing::info!(%error, "agent relay: client disconnected slot={slot}");
                    break;
                }
            },
            changed = disconnect_rx.changed() => {
                if changed.is_err() || *disconnect_rx.borrow() {
                    tracing::info!("agent relay: disconnecting stalled client slot={slot}");
                    break;
                }
                continue;
            }
            release = local_release_rx.recv() => {
                let Some(release) = release else { continue; };
                if local_write_tx.send(LocalClientWrite::Release(release)).is_err() {
                    break;
                }
                continue;
            }
        };
        #[cfg(not(unix))]
        let frame = tokio::select! {
            result = read_raw_frame(&mut reader) => match result {
                Ok(frame) => frame,
                Err(error) => {
                    tracing::info!(%error, "agent relay: client disconnected slot={slot}");
                    break;
                }
            },
            changed = disconnect_rx.changed() => {
                if changed.is_err() || *disconnect_rx.borrow() {
                    tracing::info!("agent relay: disconnecting stalled client slot={slot}");
                    break;
                }
                continue;
            }
        };

        #[cfg(unix)]
        let mut shared_bulk = None;
        #[cfg(unix)]
        if frame.id == 0 && frame.flags == 0 {
            let local = if frame.data.len() >= LEN_PREFIX_SIZE + FRAME_HEADER_SIZE {
                decode_local_body(&frame.data[LEN_PREFIX_SIZE + FRAME_HEADER_SIZE..])
            } else {
                Err(
                    microsandbox_agent_client::local_shm::LocalShmError::Protocol(
                        "local frame is shorter than its outer header".into(),
                    ),
                )
            };
            let local = match local {
                Ok(local) => local,
                Err(error) => {
                    tracing::warn!(%error, "agent relay: malformed local client frame slot={slot}");
                    break;
                }
            };
            match local {
                LocalShmFrame::UpgradeRequest => {
                    if ordinary_frame_seen || local_server.is_some() {
                        tracing::warn!(
                            "agent relay: repeated or late local transport upgrade slot={slot}"
                        );
                        break;
                    }
                    let server = match LocalShmServer::create() {
                        Ok(server) => Arc::new(server),
                        Err(error) => {
                            tracing::warn!(%error, "agent relay: create local arenas failed slot={slot}");
                            break;
                        }
                    };
                    let (completion, completed) = oneshot::channel();
                    if local_write_tx
                        .send(LocalClientWrite::Upgrade {
                            server: Arc::clone(&server),
                            completion,
                        })
                        .is_err()
                    {
                        break;
                    }
                    match completed.await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "agent relay: local arena acknowledgement failed slot={slot}");
                            break;
                        }
                        Err(_) => break,
                    }
                    {
                        let mut map = clients.lock().await;
                        let Some(client) = map.get_mut(&slot) else {
                            break;
                        };
                        client.local_outbound = Some(server.outbound.clone());
                    }
                    local_server = Some(server);
                    tracing::info!(slot, local_shm = true, "agent relay: selected local-shm-v1");
                    continue;
                }
                LocalShmFrame::BulkRelease(release) => {
                    let Some(server) = local_server.as_ref() else {
                        tracing::warn!("agent relay: local release before upgrade slot={slot}");
                        break;
                    };
                    if let Err(error) = server.outbound.release(release) {
                        tracing::warn!(%error, "agent relay: rejected local release slot={slot}");
                        break;
                    }
                    continue;
                }
                LocalShmFrame::BulkRef(descriptor) => {
                    ordinary_frame_seen = true;
                    let Some(server) = local_server.as_ref() else {
                        tracing::warn!(
                            "agent relay: local bulk reference before upgrade slot={slot}"
                        );
                        break;
                    };
                    let record = match server.inbound.receive(descriptor, local_release_tx.clone())
                    {
                        Ok(record) => record,
                        Err(error) => {
                            tracing::warn!(%error, "agent relay: rejected local bulk reference slot={slot}");
                            break;
                        }
                    };
                    frame = RawFrame {
                        data: Bytes::new(),
                        id: record.id,
                        flags: FLAG_BULK,
                    };
                    shared_bulk = Some(record);
                }
            }
        }
        #[cfg(unix)]
        if shared_bulk.is_none() {
            ordinary_frame_seen = true;
        }

        if !has_valid_frame_flags(frame.flags) {
            tracing::warn!(
                flags = frame.flags,
                id = frame.id,
                "agent relay: client slot={slot} sent an invalid flag combination"
            );
            break;
        }

        // Track session starts for disconnect cleanup.
        let is_session_start = (frame.flags & FLAG_SESSION_START) != 0;
        let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;
        let is_shutdown = (frame.flags & FLAG_SHUTDOWN) != 0;

        if !is_client_frame_allowed(frame.id, frame.flags, id_start, id_end_exclusive) {
            tracing::warn!(
                "agent relay: client slot={slot} sent out-of-range id={} range=[{}, {})",
                frame.id,
                id_start,
                id_end_exclusive
            );
            break;
        }

        // Raw bulk records and local arena messages have their own codecs.
        // All guest-bound CBOR envelopes must stay outside the host namespace.
        if frame.flags != FLAG_BULK
            && (!is_shutdown || frame.data.len() > LEN_PREFIX_SIZE + FRAME_HEADER_SIZE)
            && envelope::inspect(&frame.data[LEN_PREFIX_SIZE + FRAME_HEADER_SIZE..]).is_err()
        {
            tracing::warn!("agent relay: rejecting invalid or host-control envelope slot={slot}");
            break;
        }

        let decoded_message = (frame.flags != FLAG_BULK)
            .then(|| decode_frame(frame.data.as_ref()).ok())
            .flatten();
        let message_type = decoded_message.as_ref().map(|message| message.t);
        // A suspended guest cannot reject new work itself. Existing stream data keeps the
        // bounded transport path; this does not touch guest slot ownership or bulk state.
        if is_session_start && resident_paused.load(Ordering::Acquire) {
            let Some(request) = decoded_message.as_ref() else {
                break;
            };
            let error = CoreError {
                kind: microsandbox_protocol::core::CoreErrorKind::InvalidSession,
                message: "sandbox is paused; resume it before starting guest work".into(),
                offending_type: None,
                workload_failure: None,
            };
            let Ok(mut response) = Message::with_payload(MessageType::CoreError, frame.id, &error)
            else {
                break;
            };
            response.v = request.v;
            if queue_client_rejection(&write_tx, &write_budget, &response).is_err() {
                break;
            }
            continue;
        }
        let opened_bulk_kind = decoded_message
            .as_ref()
            .and_then(|message| match message.t {
                MessageType::FsRequest => message
                    .payload::<FsRequest>()
                    .ok()
                    .and_then(|request| request.bulk.map(|_| BulkKind::Filesystem)),
                MessageType::TcpConnect => message
                    .payload::<TcpConnect>()
                    .ok()
                    .and_then(|request| request.bulk.map(|_| BulkKind::Tcp)),
                _ => None,
            });

        if let Some(kind) = opened_bulk_kind {
            match admit_bulk_open(&active_bulk, frame.id, kind) {
                BulkOpenAdmission::Accepted => {}
                BulkOpenAdmission::Duplicate => {
                    tracing::error!(
                        id = frame.id,
                        "agent relay: client reused an active bulk correlation"
                    );
                    break;
                }
                BulkOpenAdmission::LimitReached => {
                    let version = decoded_message
                        .as_ref()
                        .expect("bulk opening was decoded")
                        .v;
                    if let Err(error) =
                        queue_bulk_open_rejection(&write_tx, &write_budget, version, frame.id, kind)
                    {
                        tracing::error!(
                            %error,
                            id = frame.id,
                            "agent relay: failed to reject excess bulk operation"
                        );
                        break;
                    }
                    // The rejected operation never enters either guest lane, so it needs no
                    // BulkCancel or merger cut. Its typed terminal is the complete lifecycle.
                    continue;
                }
            }
        }

        // The merger must know an operation exists before agentd can produce output for it. The
        // acknowledgement creates an actor-ordering cut across the command and physical lanes.
        if bulk_tx.is_some()
            && matches!(
                message_type,
                Some(MessageType::ExecRequest | MessageType::FsRequest | MessageType::TcpConnect)
            )
        {
            let incarnation = incarnation.expect("dual-port client has an incarnation");
            let (completion, completed) = oneshot::channel();
            if merge_command_tx
                .send(MergeCommand::Register {
                    incarnation,
                    id: frame.id,
                    completion,
                })
                .await
                .is_err()
                || !matches!(completed.await, Ok(Ok(())))
            {
                if opened_bulk_kind.is_some() {
                    active_bulk.lock().unwrap().remove(&frame.id);
                }
                tracing::error!(
                    id = frame.id,
                    "agent relay: failed to register client operation"
                );
                break;
            }
        }

        let bulk_metadata = if frame.flags == FLAG_BULK {
            #[cfg(unix)]
            if let Some(record) = shared_bulk.as_ref() {
                Some((
                    record.kind,
                    record.flow,
                    record.offset,
                    record.payload.len(),
                ))
            } else {
                let Ok(metadata) = bulk_wire_metadata(&frame.data) else {
                    tracing::error!(id = frame.id, "agent relay: malformed client bulk record");
                    break;
                };
                Some(metadata)
            }
            #[cfg(not(unix))]
            {
                let Ok(metadata) = bulk_wire_metadata(&frame.data) else {
                    tracing::error!(id = frame.id, "agent relay: malformed client bulk record");
                    break;
                };
                Some(metadata)
            }
        } else {
            None
        };
        if let Some((kind, flow, _, _)) = bulk_metadata {
            if flow != BulkFlow::HostToGuest {
                tracing::error!(
                    id = frame.id,
                    "agent relay: client sent a guest-to-host record"
                );
                break;
            }

            // A raw record is meaningful only after the same client opened a matching operation.
            // This prevents arbitrary IDs from creating scheduler state or consuming its budget.
            let belongs_to_active_operation =
                active_bulk.lock().unwrap().get(&frame.id).copied() == Some(kind);
            if !belongs_to_active_operation {
                tracing::error!(
                    id = frame.id,
                    ?kind,
                    "agent relay: client bulk record has no matching active operation"
                );
                break;
            }
        }

        // Cancellation is an explicit cross-lane cut. Purge both queues before the semantic
        // cancel reaches agentd so no retained record can later be associated with this ID.
        if message_type == Some(MessageType::BulkCancel)
            && let (Some(incarnation), Some(bulk_tx)) = (incarnation, &bulk_tx)
        {
            let (completion, completed) = oneshot::channel();
            if bulk_tx
                .send(BulkWriterCommand::DropFlow {
                    incarnation,
                    id: frame.id,
                    completion,
                })
                .await
                .is_err()
                || completed.await.is_err()
            {
                tracing::error!(id = frame.id, "agent relay: bulk scheduler purge failed");
                break;
            }

            let (completion, completed) = oneshot::channel();
            if merge_command_tx
                .send(MergeCommand::DropFlow {
                    incarnation,
                    id: frame.id,
                    completion,
                })
                .await
                .is_err()
                || completed.await.is_err()
            {
                tracing::error!(id = frame.id, "agent relay: bulk merger purge failed");
                break;
            }
        }

        // Forward shutdown to agentd (via the agent_tx send below) so the
        // guest can sync filesystems and power off cleanly. Also notify the
        // caller so it can start the flush-grace fallback timer — if the
        // guest's clean poweroff doesn't reach VMM exit within that window,
        // the caller force-exits as a backstop.
        if is_shutdown {
            tracing::info!("agent relay: client slot={slot} sent core.shutdown, notifying drain");
            let _ = drain_tx.try_send(());
        }

        // Register each ExecRequest in the session registry: assign a
        // relay-monotonic session id and record the pty flag. The
        // monotonic id is what users see in `exec.log` entries — it's
        // unique per session within the relay's lifetime, unlike the
        // protocol correlation id which can be reused after slot
        // recycling.
        //
        // FLAG_SESSION_START is set on both ExecRequest and FsRequest,
        // so we decode the type to disambiguate.
        let mut is_exec_session_start = false;
        if is_session_start && message_type == Some(MessageType::ExecRequest) {
            is_exec_session_start = true;
            let pty = decode_frame(frame.data.as_ref())
                .ok()
                .and_then(|msg| msg.payload::<ExecRequest>().ok())
                .map(|request| request.tty)
                .unwrap_or(false);
            let session_id = next_session_id.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut registry) = session_registry.lock() {
                registry.insert(
                    frame.id,
                    SessionInfo {
                        session_id,
                        is_pty: pty,
                    },
                );
            }
        }

        // Only acquire the lock when session bookkeeping is needed.
        // Data frames (the vast majority) skip the lock entirely.
        if is_exec_session_start || is_terminal {
            let mut map = clients.lock().await;
            if let Some(client) = map.get_mut(&slot) {
                if is_exec_session_start {
                    client.active_sessions.insert(frame.id);
                }
                if is_terminal {
                    client.active_sessions.remove(&frame.id);
                }
            }
        }

        // Raw records use the independently budgeted and fairly scheduled lane only after the
        // host/guest binding has selected dual-port mode. Combined mode retains the original FIFO.
        if frame.flags == FLAG_BULK
            && let (Some(bulk_tx), Some(bulk_budget)) = (&bulk_tx, &bulk_budget)
        {
            let incarnation = incarnation.expect("dual-port client has an incarnation");
            let (_, flow, _, payload_len) =
                bulk_metadata.expect("bulk frame metadata was validated");
            #[cfg(unix)]
            let wire_len = shared_bulk.as_ref().map_or(frame.data.len(), |record| {
                LEN_PREFIX_SIZE + FRAME_HEADER_SIZE + BULK_HEADER_SIZE + record.payload.len()
            });
            #[cfg(not(unix))]
            let wire_len = frame.data.len();
            let Ok(charged) = u32::try_from(wire_len.saturating_add(CLIENT_INCARNATION_SIZE))
            else {
                tracing::error!("agent relay: bulk frame budget overflow");
                break;
            };
            let permit = match Arc::clone(bulk_budget).acquire_many_owned(charged).await {
                Ok(permit) => permit,
                Err(_) => break,
            };
            #[cfg(unix)]
            let data = if let Some(record) = shared_bulk.take() {
                let header = match codec::encode_bulk_header(&record) {
                    Ok(header) => Bytes::copy_from_slice(&header),
                    Err(error) => {
                        tracing::error!(%error, "agent relay: encode shared bulk header failed");
                        break;
                    }
                };
                BulkWriteData::Shared {
                    header,
                    payload: record.payload,
                }
            } else {
                BulkWriteData::Inline(frame.data)
            };
            #[cfg(not(unix))]
            let data = BulkWriteData::Inline(frame.data);
            if bulk_tx
                .send(BulkWriterCommand::Write(BulkWrite {
                    id: frame.id,
                    incarnation,
                    data,
                    flow,
                    payload_len,
                    _permit: permit,
                }))
                .await
                .is_err()
            {
                tracing::error!("agent relay: bulk ring writer channel closed");
                break;
            }
        } else {
            #[cfg(unix)]
            let data = if let Some(record) = shared_bulk.take() {
                // Combined transport has one owned, ordered frame queue rather than the dual
                // port's split header/payload writer. Materialize a bounded standard raw frame
                // before releasing its arena slot; the queue then retains this copy through the
                // complete physical write. The dual-port zero-copy path above is unchanged.
                let mut encoded = Vec::with_capacity(
                    LEN_PREFIX_SIZE + FRAME_HEADER_SIZE + BULK_HEADER_SIZE + record.payload.len(),
                );
                if let Err(error) = codec::encode_bulk_to_buf(&record, &mut encoded) {
                    tracing::error!(%error, "agent relay: encode combined shared bulk frame failed");
                    break;
                }
                Bytes::from(encoded)
            } else {
                frame.data
            };
            #[cfg(not(unix))]
            let data = frame.data;
            let mut write = ControlWrite::ordinary(
                data,
                frame.id,
                frame.flags == FLAG_BULK
                    || message_type.is_some_and(MessageType::uses_workload_data_credit),
            );
            write.classify_tcp_order(frame.id, bulk_metadata, decoded_message.as_ref());
            if agent_tx.send(write).await.is_err() {
                tracing::error!("agent relay: control ring writer channel closed");
                break;
            }
        }
    }

    // Client disconnected — send SIGKILL for each active session.
    let active_sessions = {
        let mut map = clients.lock().await;
        if let Some(client) = map.remove(&slot) {
            #[cfg(unix)]
            if let Some(producer) = client.local_outbound.as_ref() {
                producer.close();
            }
            client.active_sessions
        } else {
            HashSet::new()
        }
    };

    // Tombstone the routing owner before clearing scheduler and merger state. Once the client map
    // entry is gone, a queued old frame can no longer recreate state after these acknowledged cuts.
    if let (Some(incarnation), Some(bulk_tx)) = (incarnation, &bulk_tx) {
        // Only dual-port mode owns a bulk scheduler and cross-lane merger. Combined leased mode
        // deliberately bypasses both actors, so waiting for a merger acknowledgement there would
        // quarantine every disconnected slot forever.
        {
            let (completion, completed) = oneshot::channel();
            if bulk_tx
                .send(BulkWriterCommand::DropIncarnation {
                    incarnation,
                    completion,
                })
                .await
                .is_err()
                || completed.await.is_err()
            {
                tracing::error!(
                    "agent relay: bulk scheduler cleanup failed; slot={slot} remains quarantined"
                );
                return;
            }
        }

        let (completion, completed) = oneshot::channel();
        if merge_command_tx
            .send(MergeCommand::DropIncarnation {
                incarnation,
                completion,
            })
            .await
            .is_err()
            || completed.await.is_err()
        {
            tracing::error!("agent relay: merger cleanup failed; slot={slot} remains quarantined");
            return;
        }
    }

    if !active_sessions.is_empty() {
        tracing::info!(
            "agent relay: cleaning up {} active sessions for slot={slot}",
            active_sessions.len()
        );

        for session_id in active_sessions {
            let kill_msg = match Message::with_payload(
                MessageType::ExecSignal,
                session_id,
                &ExecSignal { signal: 9 }, // SIGKILL
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!(
                        "agent relay: failed to encode SIGKILL for session {session_id}: {e}"
                    );
                    continue;
                }
            };

            let mut buf = Vec::new();
            if let Err(e) = codec::encode_to_buf(&kill_msg, &mut buf) {
                tracing::error!(
                    "agent relay: failed to encode SIGKILL frame for session {session_id}: {e}"
                );
                continue;
            }

            if agent_tx
                .send(ControlWrite::ordinary(Bytes::from(buf), session_id, false))
                .await
                .is_err()
            {
                tracing::error!("agent relay: ring writer channel closed during cleanup");
                break;
            }
        }
    }

    let disconnect_ack = match begin_relay_client_disconnect(
        &agent_tx,
        &pending_disconnects,
        id_start,
        id_end_exclusive,
        incarnation,
    )
    .await
    {
        Ok(ack) => ack,
        Err(error) => {
            // Reusing this slot after a failed disconnect would relabel untagged control output.
            // Keep it quarantined; the relay's independent writer/health paths will fail the
            // sandbox data plane if agentd is no longer reachable.
            tracing::error!(%error, "agent relay: failed to begin relay disconnect");
            return;
        }
    };
    if let Some(disconnect_ack) = disconnect_ack
        && disconnect_ack.await.is_err()
    {
        tracing::error!(
            "agent relay: disconnect acknowledgement path closed; slot={slot} remains quarantined"
        );
        return;
    }

    // Combined mode releases after enqueue as before. Dual mode reaches this point only after the
    // reverse control stream has drained through agentd's matching acknowledgement.
    used_slots.lock().await.remove(&slot);
    tracing::debug!("agent relay: slot={slot} released");
}

/// Generate a nonzero random identity for one ownership period of a relay slot.
fn random_client_incarnation() -> ClientIncarnation {
    loop {
        let incarnation = rand::random::<u128>().to_be_bytes();
        if incarnation != [0; CLIENT_INCARNATION_SIZE] {
            return incarnation;
        }
    }
}

/// Generate an incarnation that is absent from both live and quarantined ownership periods.
async fn random_unused_client_incarnation(
    clients: &Arc<Mutex<HashMap<u32, ClientState>>>,
    pending_disconnects: &Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
) -> ClientIncarnation {
    loop {
        let incarnation = random_client_incarnation();
        let live = clients
            .lock()
            .await
            .values()
            .any(|client| client.incarnation == Some(incarnation));
        if !live && !pending_disconnects.lock().await.contains_key(&incarnation) {
            return incarnation;
        }
    }
}

/// Establish one dual-port range owner before its SDK connection becomes usable.
async fn send_relay_client_connected(
    agent_tx: &ControlWriter,
    id_start: u32,
    id_end_exclusive: u32,
    incarnation: ClientIncarnation,
) -> RuntimeResult<()> {
    let frame = encode_relay_client_connected(RelayClientConnected {
        id_start,
        id_end_exclusive,
        incarnation,
    });
    agent_tx
        .send(ControlWrite::client_fence(
            Bytes::copy_from_slice(&frame),
            id_start,
            id_end_exclusive,
        ))
        .await
        .map_err(|_| RuntimeError::Custom("agent control writer stopped".into()))
}

/// Send cleanup and, in dual-port mode, register the reverse-lane drain acknowledgement first.
async fn begin_relay_client_disconnect(
    agent_tx: &ControlWriter,
    pending_disconnects: &Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
    id_start: u32,
    id_end_exclusive: u32,
    incarnation: Option<ClientIncarnation>,
) -> RuntimeResult<Option<oneshot::Receiver<()>>> {
    let receiver = if let Some(incarnation) = incarnation {
        let (completion, receiver) = oneshot::channel();
        let mut pending = pending_disconnects.lock().await;
        if pending.contains_key(&incarnation) {
            return Err(RuntimeError::Custom(
                "duplicate pending client incarnation".into(),
            ));
        }
        pending.insert(
            incarnation,
            PendingClientDisconnect {
                id_start,
                id_end_exclusive,
                completion,
            },
        );
        Some(receiver)
    } else {
        None
    };

    if let Err(error) =
        send_relay_client_disconnected(agent_tx, id_start, id_end_exclusive, incarnation).await
    {
        if let Some(incarnation) = incarnation {
            pending_disconnects.lock().await.remove(&incarnation);
        }
        return Err(error);
    }
    Ok(receiver)
}

/// Complete exactly one quarantined ownership period after its reverse control-lane cut.
async fn complete_relay_client_disconnect(
    pending_disconnects: &Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
    ack: RelayClientDisconnectedAck,
) -> RuntimeResult<()> {
    let pending = pending_disconnects.lock().await.remove(&ack.incarnation);
    let Some(pending) = pending else {
        return Err(RuntimeError::Custom(
            "agent relay: unexpected client disconnect acknowledgement".into(),
        ));
    };
    if pending.id_start != ack.id_start || pending.id_end_exclusive != ack.id_end_exclusive {
        return Err(RuntimeError::Custom(format!(
            "agent relay: disconnect acknowledgement range [{}, {}) does not match pending [{}, {})",
            ack.id_start, ack.id_end_exclusive, pending.id_start, pending.id_end_exclusive,
        )));
    }
    pending.completion.send(()).map_err(|_| {
        RuntimeError::Custom("agent relay: disconnect acknowledgement waiter stopped".into())
    })
}

/// Remove exactly the range owner that disconnected, preserving combined-mode compatibility.
async fn send_relay_client_disconnected(
    agent_tx: &ControlWriter,
    id_start: u32,
    id_end_exclusive: u32,
    incarnation: Option<ClientIncarnation>,
) -> RuntimeResult<()> {
    let message = Message::with_payload(
        MessageType::RelayClientDisconnected,
        0,
        &RelayClientDisconnected {
            id_start,
            id_end_exclusive,
            incarnation,
        },
    )
    .map_err(|error| RuntimeError::Custom(format!("encode relay lifecycle: {error}")))?;
    let mut frame = Vec::new();
    codec::encode_to_buf(&message, &mut frame)
        .map_err(|error| RuntimeError::Custom(format!("encode relay lifecycle frame: {error}")))?;
    agent_tx
        .send(ControlWrite::client_fence(
            Bytes::from(frame),
            id_start,
            id_end_exclusive,
        ))
        .await
        .map_err(|_| RuntimeError::Custom("agent control writer stopped".into()))
}

/// Publish typed cancellation for every active raw-bulk operation while control is still usable.
async fn handle_relay_transport_failure(
    agent_tx: &ControlWriter,
    merge_command_tx: &mpsc::Sender<MergeCommand>,
    clients: &Arc<Mutex<HashMap<u32, ClientState>>>,
    wait_for_terminals: bool,
) -> RuntimeResult<()> {
    let mut correlations = clients
        .lock()
        .await
        .values()
        .flat_map(|client| {
            client
                .active_bulk
                .lock()
                .unwrap()
                .iter()
                .map(|(id, kind)| (client.incarnation, *id, *kind))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    correlations.sort_unstable_by_key(|(_, id, _)| *id);

    for (incarnation, id, kind) in correlations {
        if wait_for_terminals {
            let incarnation = incarnation.ok_or_else(|| {
                RuntimeError::Custom("dual-port bulk operation is missing its incarnation".into())
            })?;
            let (completion, completed) = oneshot::channel();
            merge_command_tx
                .send(MergeCommand::DropFlow {
                    incarnation,
                    id,
                    completion,
                })
                .await
                .map_err(|_| RuntimeError::Custom("bulk merger stopped during failure".into()))?;
            completed.await.map_err(|_| {
                RuntimeError::Custom("bulk merger dropped failure completion".into())
            })?;
        }
        let cancel = Message::with_payload(
            MessageType::BulkCancel,
            id,
            &BulkCancel {
                kind,
                reason: BulkCancelReason::TransportFailure,
                message: "host agent transport failed".into(),
            },
        )
        .map_err(|error| {
            RuntimeError::Custom(format!("encode transport-failure cancellation: {error}"))
        })?;
        let mut frame = Vec::new();
        codec::encode_to_buf(&cancel, &mut frame).map_err(|error| {
            RuntimeError::Custom(format!("encode transport-failure cancel frame: {error}"))
        })?;
        let (completion, completed) = oneshot::channel();
        agent_tx
            .send(ControlWrite {
                completion: Some(completion),
                ..ControlWrite::ordinary(Bytes::from(frame), id, false)
            })
            .await
            .map_err(|_| RuntimeError::Custom("agent control writer stopped".into()))?;
        completed.await.map_err(|_| {
            RuntimeError::Custom("agent control writer dropped cancellation completion".into())
        })?;
    }

    if wait_for_terminals {
        // The caller wraps this wait in the global cleanup timeout. Keeping the relay reader alive
        // for that window lets agentd's ordinary terminal failures reach each SDK before teardown.
        loop {
            let all_terminal = clients
                .lock()
                .await
                .values()
                .all(|client| client.active_bulk.lock().unwrap().is_empty());
            if all_terminal {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    Ok(())
}

/// Return whether a client-originated frame may be forwarded to agentd.
///
/// Most client frames must use a correlation ID from the relay-assigned
/// range so responses route back to the owning client. `core.shutdown` is a
/// process-level control frame, not a correlated request, and the SDK sends it
/// with ID 0.
fn is_client_frame_allowed(id: u32, flags: u8, id_start: u32, id_end_exclusive: u32) -> bool {
    let is_shutdown_control = (flags & FLAG_SHUTDOWN) != 0 && id == 0;
    is_shutdown_control || (id >= id_start && id < id_end_exclusive)
}

/// Locate one correlation in an owner-local retirement bitmap.
fn relay_retired_bit(id: u32) -> Option<(usize, u64)> {
    let slot = relay_client_slot(id)?;
    let (id_start, _) = relay_client_id_range(slot)?;
    let local = usize::try_from(id.checked_sub(id_start)?).ok()?;
    Some((
        local / u64::BITS as usize,
        1u64 << (local % u64::BITS as usize),
    ))
}

/// Test an owner-local retirement bitmap without allocating on a read.
fn relay_correlation_is_retired(
    retired: &HashMap<ClientIncarnation, Vec<u64>>,
    incarnation: ClientIncarnation,
    id: u32,
) -> bool {
    let Some((word, mask)) = relay_retired_bit(id) else {
        return false;
    };
    retired
        .get(&incarnation)
        .and_then(|bitmap| bitmap.get(word))
        .is_some_and(|bits| bits & mask != 0)
}

/// Retire one ID in a compact bitmap bounded by the canonical per-client range size.
fn retire_relay_correlation(
    retired: &mut HashMap<ClientIncarnation, Vec<u64>>,
    incarnation: ClientIncarnation,
    id: u32,
) -> RuntimeResult<()> {
    let (word, mask) = relay_retired_bit(id).ok_or_else(|| {
        RuntimeError::Custom(format!("cannot retire unassigned correlation {id}"))
    })?;
    let bitmap = retired.entry(incarnation).or_default();
    if bitmap.len() <= word {
        bitmap.resize(word + 1, 0);
    }
    bitmap[word] |= mask;
    Ok(())
}

/// Validate the complete generation-8 flag byte without interpreting an opaque frame body.
fn has_valid_frame_flags(flags: u8) -> bool {
    matches!(
        flags,
        0 | FLAG_TERMINAL | FLAG_SESSION_START | FLAG_SHUTDOWN | FLAG_BULK
    )
}

/// Parse the fixed raw header without copying payload bytes or decoding CBOR.
fn raw_bulk_offsets(frame: &RawFrame) -> RuntimeResult<(u64, u64, BulkFlow)> {
    let header_len = LEN_PREFIX_SIZE + FRAME_HEADER_SIZE + BULK_HEADER_SIZE;
    if frame.flags != FLAG_BULK || frame.data.len() <= header_len {
        return Err(RuntimeError::Custom(
            "agent relay: malformed raw bulk frame".into(),
        ));
    }
    if frame.data[11..13] != [0, 0] {
        return Err(RuntimeError::Custom(
            "agent relay: nonzero raw bulk reserved bytes".into(),
        ));
    }
    let flow = BulkFlow::from_wire(frame.data[10]).ok_or_else(|| {
        RuntimeError::Custom(format!(
            "agent relay: unknown raw bulk flow {}",
            frame.data[10]
        ))
    })?;
    let offset = u64::from_be_bytes(
        frame.data[13..21]
            .try_into()
            .expect("validated bulk header width"),
    );
    let payload_len = frame.data.len() - header_len;
    let end = offset
        .checked_add(payload_len as u64)
        .ok_or_else(|| RuntimeError::Custom("agent relay: raw bulk offset overflow".into()))?;
    Ok((offset, end, flow))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::*;

    fn next_control_write(
        pending: &mut VecDeque<ControlWrite>,
        workload: &WorkloadControl,
    ) -> Result<Option<ControlWrite>, String> {
        select_control_write(pending, workload, None).map(|(write, _)| write)
    }

    #[cfg(unix)]
    use microsandbox_agent_client::local_shm::{
        LocalShmClient, LocalShmUpgrade, local_upgrade_request_frame, receive_local_shm_upgrade,
    };
    use microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP;
    use microsandbox_protocol::bulk::{
        BULK_FORMAT_RAW_V1, BulkKind, BulkRecord, DEFAULT_BULK_RECORD_PAYLOAD, DEFAULT_BULK_WINDOW,
    };
    use microsandbox_protocol::core::Ready;
    use microsandbox_protocol::fs::FsResponse;
    use microsandbox_protocol::transport::{
        BulkTransportReady, RelayLeaseReady, decode_bulk_ack, encode_bulk_hello,
    };

    const TEST_INCARNATION: ClientIncarnation = [0x5a; CLIENT_INCARNATION_SIZE];

    fn test_agent_endpoint(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        #[cfg(unix)]
        {
            // These tests instantiate the relay directly, bypassing the SDK's
            // hashed runtime socket resolver. Keep the synthetic socket short
            // enough for macOS sockaddr_un limits.
            PathBuf::from("/tmp")
                .join(format!(
                    "msb-runtime-relay-{name}-{}-{nanos}",
                    std::process::id()
                ))
                .join("agent.sock")
        }

        #[cfg(windows)]
        {
            PathBuf::from(format!(
                r"\\.\pipe\msb-runtime-relay-{name}-{}-{nanos}",
                std::process::id()
            ))
        }
    }

    pub(super) fn encoded_message<T: serde::Serialize>(t: MessageType, payload: &T) -> Vec<u8> {
        encoded_message_id(t, 0, payload)
    }

    pub(super) fn encoded_message_id<T: serde::Serialize>(
        t: MessageType,
        id: u32,
        payload: &T,
    ) -> Vec<u8> {
        let msg = Message::with_payload(t, id, payload).unwrap();
        let mut frame = Vec::new();
        codec::encode_to_buf(&msg, &mut frame).unwrap();
        frame
    }

    fn encoded_raw_flow(id: u32, flow: BulkFlow, offset: u64, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        codec::encode_bulk_to_buf(
            &BulkRecord {
                id,
                kind: BulkKind::Filesystem,
                flow,
                offset,
                payload: Bytes::copy_from_slice(payload),
            },
            &mut frame,
        )
        .unwrap();
        frame
    }

    fn encoded_raw(id: u32, offset: u64, payload: &'static [u8]) -> Vec<u8> {
        encoded_raw_flow(id, BulkFlow::GuestToHost, offset, payload)
    }

    fn encoded_host_raw(id: u32, offset: u64, payload: &'static [u8]) -> Vec<u8> {
        encoded_raw_flow(id, BulkFlow::HostToGuest, offset, payload)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn guest_bulk_uses_local_descriptor_when_an_arena_is_selected() {
        use std::os::fd::{BorrowedFd, OwnedFd};

        let server = LocalShmServer::create().unwrap();
        let raw_fds = server.client_fds();
        // SAFETY: The server owns both live descriptors for the duration of these duplications.
        let client_fds: [OwnedFd; 2] = unsafe {
            [
                BorrowedFd::borrow_raw(raw_fds[0])
                    .try_clone_to_owned()
                    .unwrap(),
                BorrowedFd::borrow_raw(raw_fds[1])
                    .try_clone_to_owned()
                    .unwrap(),
            ]
        };
        let client = LocalShmClient::from_fds(client_fds).unwrap();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, _disconnect_rx) = watch::channel(false);
        let clients = Arc::new(Mutex::new(HashMap::from([(
            0,
            ClientState {
                incarnation: Some(TEST_INCARNATION),
                active_sessions: HashSet::new(),
                active_bulk: Arc::new(std::sync::Mutex::new(HashMap::new())),
                write_tx,
                write_budget: Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY)),
                disconnect_tx,
                local_outbound: Some(server.outbound.clone()),
            },
        )])));
        let payload_bytes = b"guest bytes stay off the local socket";
        let payload = Bytes::from_static(payload_bytes);
        let wire = encoded_raw_flow(1, BulkFlow::GuestToHost, 9, payload_bytes);
        let lane_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_BYTE_CAPACITY));
        let lane_permit = Arc::clone(&lane_budget)
            .try_acquire_many_owned(wire.len() as u32)
            .unwrap();

        route_guest_lane_frame(
            LaneFrame {
                frame: RawFrame {
                    data: Bytes::from(wire),
                    id: 1,
                    flags: FLAG_BULK,
                },
                incarnation: Some(TEST_INCARNATION),
                _permit: lane_permit,
            },
            true,
            &clients,
            None,
            &std::sync::Mutex::new(HashMap::new()),
        )
        .await
        .unwrap();

        let ClientWriteData::LocalBulk(mut prepared) = write_rx.recv().await.unwrap().data else {
            panic!("guest bulk did not enter the local descriptor path");
        };
        let descriptor = prepared.descriptor();
        prepared.commit();
        let (release_tx, _release_rx) = mpsc::unbounded_channel();
        let received = client.inbound.receive(descriptor, release_tx).unwrap();
        assert_eq!(received.payload, payload);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_writer_preserves_local_bulk_and_terminal_order() {
        let server = LocalShmServer::create().unwrap();
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from_static(b"last tcp bytes"),
        };
        let prepared = server.outbound.try_prepare(&record).unwrap();
        let descriptor_wire = encode_local_bulk_ref(prepared.descriptor()).unwrap();
        let terminal_wire = Bytes::from_static(b"terminal-after-data");

        let (mut client_socket, server_socket) = tokio::net::UnixStream::pair().unwrap();
        let ancillary_fd = server_socket.as_fd().try_clone_to_owned().unwrap();
        let (_server_reader, server_writer) = tokio::io::split(server_socket);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (_local_write_tx, local_write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, _disconnect_rx) = watch::channel(false);
        let writer = tokio::spawn(client_writer_task(
            0,
            server_writer,
            write_rx,
            disconnect_tx,
            local_write_rx,
            ancillary_fd,
        ));
        let lane_budget = Arc::new(Semaphore::new(2));
        let client_budget = Arc::new(Semaphore::new(2));

        write_tx
            .send(ClientWrite {
                data: ClientWriteData::LocalBulk(prepared),
                _lane_permit: Some(Arc::clone(&lane_budget).acquire_owned().await.unwrap()),
                _client_permit: Arc::clone(&client_budget).acquire_owned().await.unwrap(),
            })
            .unwrap();
        write_tx
            .send(ClientWrite {
                data: ClientWriteData::Inline(terminal_wire.clone()),
                _lane_permit: Some(Arc::clone(&lane_budget).acquire_owned().await.unwrap()),
                _client_permit: Arc::clone(&client_budget).acquire_owned().await.unwrap(),
            })
            .unwrap();

        let mut received = vec![0; descriptor_wire.len() + terminal_wire.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            client_socket.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&received[..descriptor_wire.len()], descriptor_wire);
        assert_eq!(&received[descriptor_wire.len()..], terminal_wire);
        writer.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_shared_descriptor_reaches_bulk_scheduler_without_socket_payload() {
        exercise_shared_descriptor_input(true).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_shared_descriptor_combined_preserves_frame_credit_and_arena_release() {
        exercise_shared_descriptor_input(false).await;
    }

    #[cfg(unix)]
    async fn exercise_shared_descriptor_input(dual_port: bool) {
        let (mut client_socket, server_socket) = tokio::net::UnixStream::pair().unwrap();
        let ancillary_fd = server_socket.as_fd().try_clone_to_owned().unwrap();
        let (server_reader, server_writer) = tokio::io::split(server_socket);
        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (local_write_tx, local_write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, disconnect_rx) = watch::channel(false);
        let write_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY));
        let active_bulk = Arc::new(std::sync::Mutex::new(HashMap::from([(
            1,
            BulkKind::Filesystem,
        )])));
        let clients = Arc::new(Mutex::new(HashMap::from([(
            0,
            ClientState {
                incarnation: Some(TEST_INCARNATION),
                active_sessions: HashSet::new(),
                active_bulk: Arc::clone(&active_bulk),
                write_tx: write_tx.clone(),
                write_budget: Arc::clone(&write_budget),
                disconnect_tx: disconnect_tx.clone(),
                local_outbound: None,
            },
        )])));
        let writer = tokio::spawn(client_writer_task(
            0,
            server_writer,
            write_rx,
            disconnect_tx,
            local_write_rx,
            ancillary_fd,
        ));
        let (agent_tx, agent_rx) = ControlWriter::new();
        let queue_budget = agent_tx.clone();
        let expected_len = LEN_PREFIX_SIZE
            + FRAME_HEADER_SIZE
            + BULK_HEADER_SIZE
            + MAX_BULK_RECORD_PAYLOAD as usize;
        let shared = workload_test_shared(expected_len, false);
        if !dual_port {
            // Queue entries are whole owned frames. Occupy some capacity so the next full-size
            // frame must wait, without configuring a queue too small to ever admit that frame.
            shared
                .rx_ring
                .push(Bytes::from_static(b"occupied"))
                .unwrap();
        }
        let ring_writer =
            (!dual_port).then(|| tokio::spawn(ring_writer_task(Arc::clone(&shared), agent_rx)));
        let used_slots = Arc::new(Mutex::new(HashSet::from([0])));
        let (drain_tx, _drain_rx) = mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = mpsc::channel(1);
        let (merge_tx, _merge_rx) = mpsc::channel(1);
        let pending_disconnects = Arc::new(Mutex::new(HashMap::new()));
        let reader = tokio::spawn(client_reader_task(
            0,
            server_reader,
            agent_tx,
            Arc::clone(&clients),
            used_slots,
            drain_tx,
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            Arc::new(AtomicU64::new(1)),
            dual_port.then_some(bulk_tx),
            dual_port.then(|| Arc::new(Semaphore::new(BULK_WRITE_BYTE_CAPACITY))),
            merge_tx,
            pending_disconnects,
            1,
            AGENT_RELAY_ID_RANGE_STEP,
            Some(TEST_INCARNATION),
            active_bulk,
            write_tx,
            write_budget,
            disconnect_rx,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            local_write_tx,
        ));

        codec::write_raw_frame(&mut client_socket, &local_upgrade_request_frame())
            .await
            .unwrap();
        let LocalShmUpgrade::Accepted(fds) =
            receive_local_shm_upgrade(&client_socket).await.unwrap()
        else {
            panic!("runtime rejected its advertised local transport");
        };
        let local = LocalShmClient::from_fds(fds).unwrap();
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 17,
            payload: if dual_port {
                Bytes::from_static(b"arena payload")
            } else {
                Bytes::from(vec![0x53; MAX_BULK_RECORD_PAYLOAD as usize])
            },
        };
        let mut prepared = local.outbound.try_prepare(&record).unwrap();
        let descriptor = prepared.descriptor();
        let wire = encode_local_bulk_ref(descriptor).unwrap();
        client_socket.write_all(&wire).await.unwrap();
        prepared.commit();

        if dual_port {
            let command = tokio::time::timeout(Duration::from_secs(1), bulk_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let BulkWriterCommand::Write(write) = command else {
                panic!("shared record did not enter the bulk scheduler");
            };
            let BulkWriteData::Shared { payload, .. } = write.data else {
                panic!("dual-port runtime rebuilt shared input as an in-band socket frame");
            };
            assert_eq!(payload, record.payload);
        } else {
            // The arena can be released once the fallback owns its copy, even while the console
            // queue cannot admit that frame. Reusing the slot must not change the owned copy.
            let release = tokio::time::timeout(
                Duration::from_secs(1),
                codec::read_raw_frame(&mut client_socket),
            )
            .await
            .unwrap()
            .unwrap();
            let LocalShmFrame::BulkRelease(release) = decode_local_body(&release.body).unwrap()
            else {
                panic!("copied combined input did not release its arena slot");
            };
            assert_eq!(release.slot, descriptor.slot);
            assert_eq!(release.generation, descriptor.generation);
            local.outbound.release(release).unwrap();
            let replacement = BulkRecord {
                payload: Bytes::from(vec![0xa7; record.payload.len()]),
                ..record.clone()
            };
            let _replacement = local.outbound.try_prepare(&replacement).unwrap();

            tokio::time::timeout(Duration::from_secs(1), async {
                while shared.rx_ring.snapshot().full_events == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                queue_budget.data_bytes.available_permits(),
                AGENT_WRITE_DATA_BYTES - expected_len
            );
            assert_eq!(
                queue_budget.data_frames.available_permits(),
                AGENT_WRITE_CLASS_FRAMES - 1
            );
            assert_eq!(
                queue_budget.control_bytes.available_permits(),
                AGENT_WRITE_CONTROL_BYTES
            );
            assert_eq!(
                queue_budget.control_frames.available_permits(),
                AGENT_WRITE_CLASS_FRAMES
            );
            let gate = shared.workload_control.gate();
            assert_eq!(next_host_fragment(&shared).await.as_ref(), b"occupied");
            let mut wire = BytesMut::from(next_host_fragment(&shared).await.as_ref());
            assert_eq!(wire.len(), expected_len);
            let position = tokio::time::timeout(
                Duration::from_secs(1),
                shared.workload_control.parked_position(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(position.bulk_bytes, expected_len as u64);
            assert_eq!(position.bulk_frames, 1);
            assert_eq!(position.control_frames, 0);
            assert_eq!(
                queue_budget.data_bytes.available_permits(),
                AGENT_WRITE_DATA_BYTES
            );
            assert_eq!(
                queue_budget.data_frames.available_permits(),
                AGENT_WRITE_CLASS_FRAMES
            );
            let Some(codec::DecodedFrame::Bulk(received)) =
                codec::try_decode_frame_from_bytes(&mut wire).unwrap()
            else {
                panic!("combined descriptor did not produce one complete raw frame");
            };
            assert_eq!(received, record);
            assert!(wire.is_empty());
            assert!(shared.rx_ring.pop().is_none());
            gate.release();
        }

        reader.abort();
        writer.abort();
        if let Some(ring_writer) = ring_writer {
            ring_writer.abort();
            let _ = ring_writer.await;
        }
        let _ = reader.await;
        let _ = writer.await;
    }

    fn lane_frame(bytes: Vec<u8>, budget: &Arc<Semaphore>) -> LaneFrame {
        lane_frame_with_incarnation(bytes, budget, TEST_INCARNATION)
    }

    fn lane_frame_with_incarnation(
        bytes: Vec<u8>,
        budget: &Arc<Semaphore>,
        incarnation: ClientIncarnation,
    ) -> LaneFrame {
        let id = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let flags = bytes[8];
        let permit = Arc::clone(budget)
            .try_acquire_many_owned(bytes.len() as u32)
            .unwrap();
        LaneFrame {
            frame: RawFrame {
                data: Bytes::from(bytes),
                id,
                flags,
            },
            incarnation: Some(incarnation),
            _permit: permit,
        }
    }

    fn bulk_accepted() -> BulkAccepted {
        BulkAccepted {
            kind: BulkKind::Filesystem,
            flows: BULK_FLOW_MASK_GUEST_TO_HOST,
            format: BULK_FORMAT_RAW_V1,
            max_record_payload: DEFAULT_BULK_RECORD_PAYLOAD,
            host_to_guest_credit_limit: 0,
            guest_to_host_credit_limit: DEFAULT_BULK_WINDOW,
        }
    }

    #[test]
    fn client_frame_validation_allows_ids_in_assigned_range() {
        assert!(is_client_frame_allowed(10, 0, 10, 20));
        assert!(is_client_frame_allowed(19, FLAG_SESSION_START, 10, 20));
    }

    #[test]
    fn client_frame_validation_rejects_non_shutdown_ids_outside_range() {
        assert!(!is_client_frame_allowed(0, 0, 10, 20));
        assert!(!is_client_frame_allowed(9, FLAG_SESSION_START, 10, 20));
        assert!(!is_client_frame_allowed(20, FLAG_TERMINAL, 10, 20));
    }

    #[test]
    fn client_frame_validation_allows_shutdown_control_id_zero() {
        assert!(is_client_frame_allowed(0, FLAG_SHUTDOWN, 10, 20));
    }

    #[test]
    fn raw_bulk_flag_is_exclusive() {
        assert!(has_valid_frame_flags(FLAG_BULK));
        assert!(!has_valid_frame_flags(FLAG_BULK | FLAG_TERMINAL));
        assert!(!has_valid_frame_flags(0x80));
    }

    #[test]
    fn bulk_wire_metadata_validates_the_complete_fixed_header() {
        let valid = Bytes::from(encoded_host_raw(7, 11, b"payload"));
        assert_eq!(
            bulk_wire_metadata(&valid).unwrap(),
            (BulkKind::Filesystem, BulkFlow::HostToGuest, 11, 7)
        );

        let mut reserved = valid.to_vec();
        reserved[11] = 1;
        assert!(bulk_wire_metadata(&Bytes::from(reserved)).is_err());

        let mut mismatched_length = valid.to_vec();
        mismatched_length[3] -= 1;
        assert!(bulk_wire_metadata(&Bytes::from(mismatched_length)).is_err());
    }

    #[tokio::test]
    async fn control_writer_acknowledges_only_after_ring_admission() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        let (completion, completed) = oneshot::channel();
        tx.send(ControlWrite {
            completion: Some(completion),
            ..Bytes::from_static(b"control frame").into()
        })
        .await
        .unwrap();

        completed.await.unwrap();
        assert_eq!(shared.rx_ring.pop().unwrap().as_ref(), b"control frame");
        drop(tx);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn dual_port_range_stays_quarantined_until_reverse_control_ack() {
        let incarnation = [0x81; CLIENT_INCARNATION_SIZE];
        let id_start = 1;
        let id_end_exclusive = AGENT_RELAY_ID_RANGE_STEP;
        let (agent_tx, mut agent_rx) = mpsc::channel(1);
        let agent_tx = ControlWriter::from_sender(agent_tx);
        let pending = Arc::new(Mutex::new(HashMap::new()));

        let mut completion = begin_relay_client_disconnect(
            &agent_tx,
            &pending,
            id_start,
            id_end_exclusive,
            Some(incarnation),
        )
        .await
        .unwrap()
        .unwrap();
        let wire = agent_rx.recv().await.unwrap();
        let message = decode_frame(wire.data.as_ref()).unwrap();
        let disconnected: RelayClientDisconnected = message.payload().unwrap();
        assert_eq!(disconnected.incarnation, Some(incarnation));
        assert!(pending.lock().await.contains_key(&incarnation));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut completion)
                .await
                .is_err()
        );

        complete_relay_client_disconnect(
            &pending,
            RelayClientDisconnectedAck {
                id_start,
                id_end_exclusive,
                incarnation,
            },
        )
        .await
        .unwrap();
        completion.await.unwrap();
        assert!(!pending.lock().await.contains_key(&incarnation));
    }

    #[tokio::test]
    async fn paused_client_rejects_work_without_registering_or_forwarding_sessions() {
        let slot = 0;
        let incarnation = [0x82; CLIENT_INCARNATION_SIZE];
        let (id_start, id_end_exclusive) = relay_client_id_range(slot).unwrap();
        let (reader, mut peer) = tokio::io::duplex(4096);
        let (agent_tx, mut agent_rx) = mpsc::channel(4);
        let agent_tx = ControlWriter::from_sender(agent_tx);
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        #[cfg(unix)]
        let (local_write_tx, _local_write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, disconnect_rx) = watch::channel(false);
        let write_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY));
        let active_bulk = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let clients = Arc::new(Mutex::new(HashMap::from([(
            slot,
            ClientState {
                incarnation: Some(incarnation),
                active_sessions: HashSet::new(),
                active_bulk: Arc::clone(&active_bulk),
                write_tx: write_tx.clone(),
                write_budget: Arc::clone(&write_budget),
                disconnect_tx,
                #[cfg(unix)]
                local_outbound: None,
            },
        )])));
        let used_slots = Arc::new(Mutex::new(HashSet::from([slot])));
        let (drain_tx, _drain_rx) = mpsc::channel(1);
        let (merge_command_tx, _merge_command_rx) = mpsc::channel(1);
        let pending_disconnects = Arc::new(Mutex::new(HashMap::new()));

        let task = tokio::spawn(client_reader_task(
            slot,
            reader,
            agent_tx,
            Arc::clone(&clients),
            Arc::clone(&used_slots),
            drain_tx,
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            Arc::new(AtomicU64::new(1)),
            None,
            None,
            merge_command_tx,
            Arc::clone(&pending_disconnects),
            id_start,
            id_end_exclusive,
            Some(incarnation),
            Arc::clone(&active_bulk),
            write_tx,
            Arc::clone(&write_budget),
            disconnect_rx,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            #[cfg(unix)]
            local_write_tx,
        ));

        let initial_budget = write_budget.available_permits();
        for kind in [MessageType::FsRequest, MessageType::ExecRequest] {
            let wire = encoded_message_id(kind, id_start, &serde_json::json!({}));
            peer.write_all(&wire).await.unwrap();
            let rejected = tokio::time::timeout(Duration::from_secs(1), write_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let ClientWriteData::Inline(bytes) = &rejected.data else {
                panic!("pause rejection must use the bounded control lane");
            };
            let response = decode_frame(bytes).unwrap();
            assert_eq!(response.id, id_start);
            assert_eq!(response.t, MessageType::CoreError);
            assert_eq!(response.v, decode_frame(&wire).unwrap().v);
            let error: CoreError = response.payload().unwrap();
            assert!(error.message.contains("sandbox is paused"));
            assert!(agent_rx.try_recv().is_err());
            assert!(active_bulk.lock().unwrap().is_empty());
            assert!(clients.lock().await[&slot].active_sessions.is_empty());
            assert!(write_budget.available_permits() < initial_budget);
            drop(rejected);
            assert_eq!(write_budget.available_permits(), initial_budget);
        }
        // Existing streams still enter bounded source-owned admission while paused. Classification
        // reuses this reader's already decoded envelope, including empty stdin/TCP EOF payloads.
        for (kind, uses_data_credit) in [
            (MessageType::ExecStdin, true),
            (MessageType::FsData, true),
            (MessageType::TcpData, true),
            (MessageType::TcpEof, true),
            (MessageType::BulkFinish, false),
            (MessageType::BulkCredit, false),
            (MessageType::Ping, false),
        ] {
            let wire = encoded_message_id(kind, id_start, &serde_json::json!({}));
            peer.write_all(&wire).await.unwrap();
            let admitted = tokio::time::timeout(Duration::from_secs(1), agent_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(admitted.data.as_ref(), wire);
            assert_eq!(admitted.uses_data_credit, uses_data_credit, "{kind:?}");
            assert!(matches!(admitted.order, ControlOrder::Correlation(id) if id == id_start));
        }
        active_bulk
            .lock()
            .unwrap()
            .insert(id_start, BulkKind::Filesystem);
        let raw = encoded_host_raw(id_start, 0, b"raw input");
        peer.write_all(&raw).await.unwrap();
        let admitted = tokio::time::timeout(Duration::from_secs(1), agent_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(admitted.uses_data_credit);
        assert_eq!(admitted.data.as_ref(), raw);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn combined_leased_disconnect_releases_slot_without_a_merger() {
        let slot = 0;
        let incarnation = [0x82; CLIENT_INCARNATION_SIZE];
        let (id_start, id_end_exclusive) = relay_client_id_range(slot).unwrap();
        let (reader, peer) = tokio::io::duplex(64);
        drop(peer);
        let (agent_tx, mut agent_rx) = mpsc::channel(4);
        let agent_tx = ControlWriter::from_sender(agent_tx);
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        #[cfg(unix)]
        let (local_write_tx, _local_write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, disconnect_rx) = watch::channel(false);
        let write_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY));
        let active_bulk = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let clients = Arc::new(Mutex::new(HashMap::from([(
            slot,
            ClientState {
                incarnation: Some(incarnation),
                active_sessions: HashSet::new(),
                active_bulk: Arc::clone(&active_bulk),
                write_tx: write_tx.clone(),
                write_budget: Arc::clone(&write_budget),
                disconnect_tx,
                #[cfg(unix)]
                local_outbound: None,
            },
        )])));
        let used_slots = Arc::new(Mutex::new(HashSet::from([slot])));
        let (drain_tx, _drain_rx) = mpsc::channel(1);
        let (merge_command_tx, _merge_command_rx) = mpsc::channel(1);
        let pending_disconnects = Arc::new(Mutex::new(HashMap::new()));

        let task = tokio::spawn(client_reader_task(
            slot,
            reader,
            agent_tx,
            Arc::clone(&clients),
            Arc::clone(&used_slots),
            drain_tx,
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            Arc::new(AtomicU64::new(1)),
            None,
            None,
            merge_command_tx,
            Arc::clone(&pending_disconnects),
            id_start,
            id_end_exclusive,
            Some(incarnation),
            active_bulk,
            write_tx,
            write_budget,
            disconnect_rx,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(unix)]
            local_write_tx,
        ));

        // Combined mode has no merger actor. Its ordered disconnect reaches agentd directly and
        // the reverse acknowledgement remains the sole cut before the range can be recycled.
        let wire = tokio::time::timeout(Duration::from_secs(1), agent_rx.recv())
            .await
            .expect("combined disconnect waited for an absent merger")
            .expect("combined control writer stopped");
        let message = decode_frame(wire.data.as_ref()).unwrap();
        let disconnected: RelayClientDisconnected = message.payload().unwrap();
        assert_eq!(disconnected.incarnation, Some(incarnation));

        complete_relay_client_disconnect(
            &pending_disconnects,
            RelayClientDisconnectedAck {
                id_start,
                id_end_exclusive,
                incarnation,
            },
        )
        .await
        .unwrap();
        task.await.unwrap();

        assert!(clients.lock().await.is_empty());
        assert!(used_slots.lock().await.is_empty());
    }

    #[test]
    fn guest_merger_restores_cross_lane_stream_order() {
        let id = 17;
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();

        let accepted = merger
            .push(lane_frame(
                encoded_message_id(MessageType::BulkAccepted, id, &bulk_accepted()),
                &budget,
            ))
            .unwrap();
        assert_eq!(accepted.len(), 1);

        assert!(
            merger
                .push(lane_frame(encoded_raw(id, 3, b"def"), &budget))
                .unwrap()
                .is_empty()
        );
        assert!(
            merger
                .push(lane_frame(
                    encoded_message_id(
                        MessageType::BulkFinish,
                        id,
                        &BulkFinish {
                            kind: BulkKind::Filesystem,
                            flow: BulkFlow::GuestToHost,
                            final_offset: 6,
                        },
                    ),
                    &budget,
                ))
                .unwrap()
                .is_empty()
        );
        assert!(
            merger
                .push(lane_frame(
                    encoded_message_id(
                        MessageType::FsResponse,
                        id,
                        &FsResponse {
                            ok: true,
                            error: None,
                            data: None,
                        },
                    ),
                    &budget,
                ))
                .unwrap()
                .is_empty()
        );

        let ready = merger
            .push(lane_frame(encoded_raw(id, 0, b"abc"), &budget))
            .unwrap();
        assert_eq!(ready.len(), 4);
        assert_eq!(raw_bulk_offsets(&ready[0].frame).unwrap().0, 0);
        assert_eq!(raw_bulk_offsets(&ready[1].frame).unwrap().0, 3);
        assert_eq!(
            decode_frame(ready[2].frame.data.as_ref()).unwrap().t,
            MessageType::BulkFinish
        );
        assert_eq!(
            decode_frame(ready[3].frame.data.as_ref()).unwrap().t,
            MessageType::FsResponse
        );
        assert!(!merger.flows.contains_key(&(TEST_INCARNATION, id)));
    }

    #[test]
    fn guest_merger_holds_raw_until_acceptance() {
        let id = 29;
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();

        assert!(
            merger
                .push(lane_frame(encoded_raw(id, 0, b"payload"), &budget))
                .unwrap()
                .is_empty()
        );
        let ready = merger
            .push(lane_frame(
                encoded_message_id(MessageType::BulkAccepted, id, &bulk_accepted()),
                &budget,
            ))
            .unwrap();

        assert_eq!(ready.len(), 2);
        assert_eq!(
            decode_frame(ready[0].frame.data.as_ref()).unwrap().t,
            MessageType::BulkAccepted
        );
        assert_eq!(raw_bulk_offsets(&ready[1].frame).unwrap().0, 0);
    }

    #[test]
    fn guest_merger_disconnect_releases_held_lane_budget() {
        let id = 41;
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let full_budget = budget.available_permits();
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();

        merger
            .push(lane_frame(encoded_raw(id, 16, b"held"), &budget))
            .unwrap();
        assert!(budget.available_permits() < full_budget);

        merger.drop_incarnation(TEST_INCARNATION);

        assert_eq!(budget.available_permits(), full_budget);
    }

    #[test]
    fn guest_merger_never_mixes_recycled_range_incarnations() {
        let id = 47;
        let old = [0x11; CLIENT_INCARNATION_SIZE];
        let new = [0x22; CLIENT_INCARNATION_SIZE];
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let mut merger = GuestFrameMerger::default();
        merger.register(old, id).unwrap();
        merger.register(new, id).unwrap();

        assert!(
            merger
                .push(lane_frame_with_incarnation(
                    encoded_raw(id, 0, b"old"),
                    &budget,
                    old,
                ))
                .unwrap()
                .is_empty()
        );
        let accepted = merger
            .push(lane_frame_with_incarnation(
                encoded_message_id(MessageType::BulkAccepted, id, &bulk_accepted()),
                &budget,
                new,
            ))
            .unwrap();
        assert_eq!(accepted.len(), 1);

        merger.drop_incarnation(old);
        assert!(!merger.flows.contains_key(&(old, id)));
        assert!(merger.flows.contains_key(&(new, id)));

        let ready = merger
            .push(lane_frame_with_incarnation(
                encoded_raw(id, 0, b"new"),
                &budget,
                new,
            ))
            .unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].incarnation, Some(new));
    }

    #[test]
    fn guest_merger_enforces_per_flow_reorder_budget() {
        const PAYLOAD: &[u8] = &[0x2d; 1024 * 1024];

        let id = 53;
        let budget = Arc::new(Semaphore::new(16 * 1024 * 1024));
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();
        for record in 0..8 {
            let offset = 1 + record * PAYLOAD.len() as u64;
            assert!(
                merger
                    .push(lane_frame(encoded_raw(id, offset, PAYLOAD), &budget))
                    .unwrap()
                    .is_empty()
            );
        }

        let error = merger
            .push(lane_frame(
                encoded_raw(id, 1 + 8 * PAYLOAD.len() as u64, PAYLOAD),
                &budget,
            ))
            .err()
            .expect("ninth mebibyte must exceed the per-flow merge budget");

        assert!(error.to_string().contains("exceeded merge byte budget"));
    }

    #[test]
    fn guest_merger_rejects_overlapping_raw_intervals() {
        let id = 59;
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();

        merger
            .push(lane_frame(encoded_raw(id, 10, b"0123456789"), &budget))
            .unwrap();
        let error = merger
            .push(lane_frame(encoded_raw(id, 5, b"overlap"), &budget))
            .err()
            .expect("overlap must be rejected");

        assert!(error.to_string().contains("overlapping raw record"));
    }

    #[test]
    fn guest_merger_cancel_releases_data_and_discards_late_raw() {
        let id = 61;
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let full_budget = budget.available_permits();
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();
        merger
            .push(lane_frame(
                encoded_message_id(MessageType::BulkAccepted, id, &bulk_accepted()),
                &budget,
            ))
            .unwrap();
        merger
            .push(lane_frame(encoded_raw(id, 10, b"held"), &budget))
            .unwrap();
        merger
            .push(lane_frame(
                encoded_message_id(
                    MessageType::FsResponse,
                    id,
                    &FsResponse {
                        ok: false,
                        error: Some("cancelled".into()),
                        data: None,
                    },
                ),
                &budget,
            ))
            .unwrap();

        merger.drop_flow(TEST_INCARNATION, id);
        assert_eq!(budget.available_permits(), full_budget);
        let ready = merger
            .push(lane_frame(
                encoded_message_id(
                    MessageType::FsResponse,
                    id,
                    &FsResponse {
                        ok: false,
                        error: Some("cancelled".into()),
                        data: None,
                    },
                ),
                &budget,
            ))
            .unwrap();
        assert_eq!(ready.len(), 1);
        drop(ready);
        assert_eq!(budget.available_permits(), full_budget);
        assert!(
            merger
                .push(lane_frame(encoded_raw(id, 0, b"late"), &budget))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn guest_merger_keeps_guest_cancel_route_until_terminal() {
        let id = 67;
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let full_budget = budget.available_permits();
        let mut merger = GuestFrameMerger::default();
        merger.register(TEST_INCARNATION, id).unwrap();
        merger
            .push(lane_frame(
                encoded_message_id(MessageType::BulkAccepted, id, &bulk_accepted()),
                &budget,
            ))
            .unwrap();
        merger
            .push(lane_frame(encoded_raw(id, 10, b"held"), &budget))
            .unwrap();

        let cancel = merger
            .push(lane_frame(
                encoded_message_id(
                    MessageType::BulkCancel,
                    id,
                    &BulkCancel {
                        kind: BulkKind::Filesystem,
                        reason: BulkCancelReason::TransportFailure,
                        message: "test failure".into(),
                    },
                ),
                &budget,
            ))
            .unwrap();
        assert_eq!(cancel.len(), 1);
        assert!(merger.flows.contains_key(&(TEST_INCARNATION, id)));
        drop(cancel);
        assert_eq!(budget.available_permits(), full_budget);
        assert!(
            merger
                .push(lane_frame(encoded_raw(id, 0, b"late"), &budget))
                .unwrap()
                .is_empty()
        );

        let terminal = merger
            .push(lane_frame(
                encoded_message_id(
                    MessageType::FsResponse,
                    id,
                    &FsResponse {
                        ok: false,
                        error: Some("test failure".into()),
                        data: None,
                    },
                ),
                &budget,
            ))
            .unwrap();
        assert_eq!(terminal.len(), 1);
        assert!(!merger.flows.contains_key(&(TEST_INCARNATION, id)));
        assert!(merger.register(TEST_INCARNATION, id).is_err());
    }

    #[test]
    fn bulk_scheduler_drop_flow_releases_queued_capacity() {
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let full_budget = budget.available_permits();
        let data = Bytes::from(encoded_host_raw(1, 0, b"queued"));
        let permit = budget
            .clone()
            .try_acquire_many_owned(data.len() as u32)
            .unwrap();
        let mut flows = HashMap::new();
        let mut active = VecDeque::new();
        let mut retired = HashMap::new();
        apply_bulk_writer_command(
            BulkWriterCommand::Write(BulkWrite {
                id: 1,
                incarnation: TEST_INCARNATION,
                data: BulkWriteData::Inline(data),
                flow: BulkFlow::HostToGuest,
                payload_len: b"queued".len(),
                _permit: permit,
            }),
            &mut flows,
            &mut active,
            &mut retired,
        )
        .unwrap();
        assert!(budget.available_permits() < full_budget);

        let (completion, mut completed) = oneshot::channel();
        apply_bulk_writer_command(
            BulkWriterCommand::DropFlow {
                incarnation: TEST_INCARNATION,
                id: 1,
                completion,
            },
            &mut flows,
            &mut active,
            &mut retired,
        )
        .unwrap();

        assert_eq!(completed.try_recv(), Ok(()));
        assert_eq!(budget.available_permits(), full_budget);
        assert!(flows.is_empty());
        assert!(active.is_empty());
        assert!(relay_correlation_is_retired(&retired, TEST_INCARNATION, 1));

        let late_data = Bytes::from(encoded_host_raw(1, 0, b"late"));
        let late_permit = budget
            .clone()
            .try_acquire_many_owned(late_data.len() as u32)
            .unwrap();
        apply_bulk_writer_command(
            BulkWriterCommand::Write(BulkWrite {
                id: 1,
                incarnation: TEST_INCARNATION,
                data: BulkWriteData::Inline(late_data),
                flow: BulkFlow::HostToGuest,
                payload_len: b"late".len(),
                _permit: late_permit,
            }),
            &mut flows,
            &mut active,
            &mut retired,
        )
        .unwrap();
        assert_eq!(budget.available_permits(), full_budget);
        assert!(flows.is_empty());
    }

    #[tokio::test]
    async fn bulk_lane_rejects_control_frames() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let (frame_tx, _frame_rx) = mpsc::channel(1);
        let budget = Arc::new(Semaphore::new(64 * 1024));
        let mut wire = TEST_INCARNATION.to_vec();
        wire.extend_from_slice(&encoded_message(
            MessageType::Pong,
            &microsandbox_protocol::core::Pong {},
        ));
        shared.tx_ring.push(wire).unwrap();
        shared.tx_wake.wake();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            lane_reader_task(
                BytesMut::new(),
                Arc::clone(&shared),
                GuestLane::Bulk,
                true,
                true,
                frame_tx,
                budget,
                Arc::clone(&shared.workload_control),
            ),
        )
        .await
        .expect("bulk lane reader stalled")
        .unwrap_err();

        assert!(error.to_string().contains("non-bulk frame"));
        assert!(shared.is_closed());
    }

    #[tokio::test]
    async fn bulk_scheduler_services_another_flow_before_draining_a_large_flow() {
        const RECORDS: usize = 8;
        const PAYLOAD: &[u8] = &[0x5a; 128 * 1024];

        let shared = Arc::new(ConsoleSharedState::with_capacity(2 * 1024 * 1024));
        let budget = Arc::new(Semaphore::new(2 * 1024 * 1024));
        let (tx, rx) = mpsc::channel(RECORDS + 1);
        for offset in 0..RECORDS {
            let data = Bytes::from(encoded_host_raw(
                1,
                (offset * PAYLOAD.len()) as u64,
                PAYLOAD,
            ));
            let permit = Arc::clone(&budget)
                .acquire_many_owned(data.len() as u32)
                .await
                .unwrap();
            tx.send(BulkWriterCommand::Write(BulkWrite {
                id: 1,
                incarnation: TEST_INCARNATION,
                data: BulkWriteData::Inline(data),
                flow: BulkFlow::HostToGuest,
                payload_len: PAYLOAD.len(),
                _permit: permit,
            }))
            .await
            .unwrap();
        }
        let data = Bytes::from(encoded_host_raw(2, 0, PAYLOAD));
        let permit = Arc::clone(&budget)
            .acquire_many_owned(data.len() as u32)
            .await
            .unwrap();
        tx.send(BulkWriterCommand::Write(BulkWrite {
            id: 2,
            incarnation: TEST_INCARNATION,
            data: BulkWriteData::Inline(data),
            flow: BulkFlow::HostToGuest,
            payload_len: PAYLOAD.len(),
            _permit: permit,
        }))
        .await
        .unwrap();
        drop(tx);

        let task = tokio::spawn(bulk_ring_writer_task(
            Arc::clone(&shared),
            rx,
            Arc::clone(&shared.workload_control),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("bulk scheduler stalled")
            .unwrap()
            .unwrap();

        let mut wire = BytesMut::new();
        while let Some(fragment) = shared.rx_ring.pop() {
            wire.extend_from_slice(&fragment);
        }
        let mut order = Vec::new();
        while let Some(frame) = try_decode_incarnated_bulk_from_bytes(&mut wire).unwrap() {
            assert_eq!(frame.incarnation, TEST_INCARNATION);
            order.push(frame.record.id);
        }
        assert_eq!(order.len(), RECORDS + 1);
        let second_flow_index = order.iter().position(|id| *id == 2).unwrap();
        assert!(
            second_flow_index < RECORDS,
            "large flow drained before the competing flow: {order:?}"
        );
    }

    #[tokio::test]
    async fn bulk_scheduler_admits_one_maximum_filesystem_record() {
        let capacity = 4 * 1024 * 1024;
        let shared = Arc::new(ConsoleSharedState::with_capacity(capacity));
        let budget = Arc::new(Semaphore::new(capacity));
        let (tx, rx) = mpsc::channel(1);
        let record = BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from(vec![0x5a; MAX_BULK_RECORD_PAYLOAD as usize]),
        };
        let mut encoded = Vec::new();
        codec::encode_bulk_to_buf(&record, &mut encoded).unwrap();
        let data = Bytes::from(encoded);
        let permit = Arc::clone(&budget)
            .acquire_many_owned(data.len() as u32)
            .await
            .unwrap();
        tx.send(BulkWriterCommand::Write(BulkWrite {
            id: record.id,
            incarnation: TEST_INCARNATION,
            data: BulkWriteData::Inline(data),
            flow: record.flow,
            payload_len: record.payload.len(),
            _permit: permit,
        }))
        .await
        .unwrap();
        drop(tx);

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bulk_ring_writer_task(
                Arc::clone(&shared),
                rx,
                Arc::clone(&shared.workload_control),
            ),
        )
        .await
        .expect("maximum filesystem record stalled")
        .unwrap();

        let mut wire = BytesMut::new();
        while let Some(fragment) = shared.rx_ring.pop() {
            wire.extend_from_slice(&fragment);
        }
        let decoded = try_decode_incarnated_bulk_from_bytes(&mut wire)
            .unwrap()
            .expect("maximum filesystem record was emitted");
        assert_eq!(decoded.incarnation, TEST_INCARNATION);
        assert_eq!(
            decoded.record.payload.len(),
            MAX_BULK_RECORD_PAYLOAD as usize
        );
        assert!(wire.is_empty());
        assert_eq!(budget.available_permits(), capacity);
    }

    #[tokio::test]
    async fn client_batch_handles_short_vectored_writes_and_releases_budget() {
        let lane_budget = Arc::new(Semaphore::new(8));
        let client_budget = Arc::new(Semaphore::new(8));
        let first_lane = Arc::clone(&lane_budget)
            .acquire_many_owned(3)
            .await
            .unwrap();
        let first_client = Arc::clone(&client_budget)
            .acquire_many_owned(3)
            .await
            .unwrap();
        let second_lane = Arc::clone(&lane_budget)
            .acquire_many_owned(5)
            .await
            .unwrap();
        let second_client = Arc::clone(&client_budget)
            .acquire_many_owned(5)
            .await
            .unwrap();
        let mut batch = VecDeque::from([
            ClientWrite {
                data: ClientWriteData::Inline(Bytes::from_static(b"abc")),
                _lane_permit: Some(first_lane),
                _client_permit: first_client,
            },
            ClientWrite {
                data: ClientWriteData::Inline(Bytes::from_static(b"defgh")),
                _lane_permit: Some(second_lane),
                _client_permit: second_client,
            },
        ]);
        let mut writer = ShortVectoredWriter {
            max_write: 2,
            ..Default::default()
        };

        write_client_batch(&mut writer, &mut batch).await.unwrap();

        assert_eq!(writer.bytes, b"abcdefgh");
        assert!(batch.is_empty());
        assert_eq!(lane_budget.available_permits(), 8);
        assert_eq!(client_budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn client_mailbox_absorbs_more_than_two_large_frames_without_blocking() {
        const FRAME_BYTES: usize = 3 * 1024 * 1024;
        const FRAME_COUNT: usize = 3;

        let lane_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_BYTE_CAPACITY));
        let client_budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY));
        let (tx, mut rx) = mpsc::unbounded_channel();

        for _ in 0..FRAME_COUNT {
            let lane_permit = Arc::clone(&lane_budget)
                .try_acquire_many_owned(FRAME_BYTES as u32)
                .unwrap();
            let client_permit = Arc::clone(&client_budget)
                .try_acquire_many_owned(FRAME_BYTES as u32)
                .unwrap();
            tx.send(ClientWrite {
                data: ClientWriteData::Inline(Bytes::from(vec![0u8; FRAME_BYTES])),
                _lane_permit: Some(lane_permit),
                _client_permit: client_permit,
            })
            .unwrap();
        }

        assert_eq!(rx.len(), FRAME_COUNT);
        while rx.recv().await.is_some() {
            if rx.is_empty() {
                break;
            }
        }
        assert_eq!(lane_budget.available_permits(), CLIENT_OUTPUT_BYTE_CAPACITY);
        assert_eq!(
            client_budget.available_permits(),
            CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY
        );
    }

    #[tokio::test]
    async fn combined_reader_routes_directly_without_a_lane_actor() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, _disconnect_rx) = watch::channel(false);
        let clients = Arc::new(Mutex::new(HashMap::from([(
            0,
            ClientState {
                incarnation: None,
                active_sessions: HashSet::new(),
                active_bulk: Arc::new(std::sync::Mutex::new(HashMap::new())),
                write_tx,
                write_budget: Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY)),
                disconnect_tx,
                #[cfg(unix)]
                local_outbound: None,
            },
        )])));
        let frame = encoded_message_id(MessageType::Pong, 1, &microsandbox_protocol::core::Pong {});
        let reader = tokio::spawn(combined_ring_reader_task(
            BytesMut::new(),
            Arc::clone(&shared),
            false,
            clients,
            None,
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
        ));

        shared.tx_ring.push(frame.clone()).unwrap();
        shared.tx_wake.wake();
        let output = tokio::time::timeout(Duration::from_secs(1), write_rx.recv())
            .await
            .expect("combined reader stalled")
            .expect("combined client writer stopped");

        let ClientWriteData::Inline(output) = output.data else {
            panic!("combined control output unexpectedly used the local bulk path");
        };
        assert_eq!(output.as_ref(), frame);
        reader.abort();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn wait_ready_rejects_ready_before_init_when_maps_are_pending() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let handle = Arc::new(std::sync::OnceLock::new());
        let sock_path = test_agent_endpoint("ready-before-init");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap()
            .with_bind_identity_map(Some(Arc::clone(&handle)), 1);

        shared
            .tx_ring
            .push(encoded_message(
                MessageType::Ready,
                &Ready {
                    boot_time_ns: 0,
                    init_time_ns: 0,
                    ready_time_ns: 0,
                    ..Default::default()
                },
            ))
            .unwrap();
        shared.tx_wake.wake();

        let err = relay.wait_ready().unwrap_err();
        assert!(
            err.to_string()
                .contains("received core.ready before init context resolution")
        );
        assert!(handle.get().is_none());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn wait_ready_installs_init_map_before_ready() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let handle = Arc::new(std::sync::OnceLock::new());
        let sock_path = test_agent_endpoint("init-map");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap()
            .with_bind_identity_map(Some(Arc::clone(&handle)), 2);

        shared
            .tx_ring
            .push(encoded_message(
                MessageType::InitResolved,
                &InitResolved {
                    default_user: microsandbox_protocol::core::ResolvedUser {
                        uid: 1000,
                        gid: 1001,
                    },
                },
            ))
            .unwrap();
        shared
            .tx_ring
            .push(encoded_message(
                MessageType::Ready,
                &Ready {
                    boot_time_ns: 0,
                    init_time_ns: 0,
                    ready_time_ns: 0,
                    ..Default::default()
                },
            ))
            .unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        assert_eq!(
            handle.get().copied(),
            Some(BindIdentityMap::new(
                unsafe { libc::getuid() as u32 },
                1000,
                1001
            ))
        );
        assert!(shared.rx_ring.pop().is_some(), "host should ack agentd");
    }

    #[tokio::test]
    async fn wait_ready_skips_init_requirement_when_no_bind_map_pending() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let sock_path = test_agent_endpoint("no-bind-map");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap();
        #[cfg(unix)]
        {
            relay = relay.with_bind_identity_map(None, 0);
        }

        let ready = encoded_message(
            MessageType::Ready,
            &Ready {
                boot_time_ns: 0,
                init_time_ns: 0,
                ready_time_ns: 0,
                workload_transport_barrier_version: Some(WORKLOAD_TRANSPORT_BARRIER_VERSION),
                ..Default::default()
            },
        );
        shared.tx_ring.push(ready.clone()).unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        let _private = shared.workload_control.start();
        let (_, captured_ready) = shared.workload_control.ready().unwrap();
        #[cfg(unix)]
        assert_eq!(
            captured_ready.local_transport,
            Some(LocalTransportReady::shared_arena_v1())
        );
        #[cfg(not(unix))]
        assert!(captured_ready.local_transport.is_none());

        let cached = relay.ready_frame.as_ref().expect("SDK-facing ready frame");
        let cached_ready: Ready = decode_frame(cached).unwrap().payload().unwrap();
        #[cfg(unix)]
        assert_eq!(
            cached_ready.local_transport,
            Some(LocalTransportReady::shared_arena_v1())
        );
        #[cfg(not(unix))]
        assert!(cached_ready.local_transport.is_none());
        assert!(
            shared.rx_ring.pop().is_none(),
            "no init context means no ack should be sent"
        );
    }

    #[tokio::test]
    async fn wait_ready_binds_fragmented_bulk_hello_to_advertised_capability() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let bulk_shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let sock_path = test_agent_endpoint("dual-port-binding");
        let mut relay = AgentRelay::new_with_bulk(
            &sock_path,
            Arc::clone(&shared),
            Some(Arc::clone(&bulk_shared)),
        )
        .await
        .unwrap();
        let connection_id = [0xa7; 16];

        for fragment in encode_bulk_hello(connection_id).chunks(2) {
            bulk_shared.tx_ring.push(fragment.to_vec()).unwrap();
        }
        bulk_shared.tx_wake.wake();
        shared
            .tx_ring
            .push(encoded_message(
                MessageType::Ready,
                &Ready {
                    boot_time_ns: 0,
                    init_time_ns: 0,
                    ready_time_ns: 0,
                    bulk_transport: Some(BulkTransportReady::dual_port_v1(connection_id)),
                    relay_lease: Some(RelayLeaseReady::range_lease_v1()),
                    ..Default::default()
                },
            ))
            .unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        assert!(relay.dual_port_active);
        assert_eq!(relay.bulk_connection_id, Some(connection_id));
        let ack = bulk_shared
            .rx_ring
            .pop()
            .expect("host binding acknowledgement");
        decode_bulk_ack(&ack, connection_id).unwrap();
    }

    #[tokio::test]
    async fn wait_ready_falls_back_when_agent_does_not_bind_bulk_port() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let bulk_shared = Arc::new(ConsoleSharedState::with_capacity(64 * 1024));
        let sock_path = test_agent_endpoint("dual-port-fallback");
        let mut relay = AgentRelay::new_with_bulk(
            &sock_path,
            Arc::clone(&shared),
            Some(Arc::clone(&bulk_shared)),
        )
        .await
        .unwrap();

        shared
            .tx_ring
            .push(encoded_message(
                MessageType::Ready,
                &Ready {
                    boot_time_ns: 0,
                    init_time_ns: 0,
                    ready_time_ns: 0,
                    ..Default::default()
                },
            ))
            .unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        assert!(!relay.dual_port_active);
        assert!(bulk_shared.is_closed());
    }

    #[test]
    fn bulk_open_admission_rejects_only_the_excess_operation() {
        let active = std::sync::Mutex::new(HashMap::new());
        for id in 1..=BULK_WRITE_MAX_FLOWS_PER_CLIENT as u32 {
            assert_eq!(
                admit_bulk_open(&active, id, BulkKind::Filesystem),
                BulkOpenAdmission::Accepted
            );
        }

        assert_eq!(
            admit_bulk_open(&active, 1, BulkKind::Filesystem),
            BulkOpenAdmission::Duplicate
        );
        assert_eq!(
            admit_bulk_open(&active, 1000, BulkKind::Tcp),
            BulkOpenAdmission::LimitReached
        );
        assert_eq!(
            active.lock().unwrap().len(),
            BULK_WRITE_MAX_FLOWS_PER_CLIENT
        );
    }

    #[test]
    fn bulk_open_rejection_is_typed_terminal_at_the_request_version() {
        let (write_tx, mut write_rx) = mpsc::unbounded_channel();
        let budget = Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY));
        let version = microsandbox_protocol::message::PROTOCOL_VERSION - 1;

        for (id, kind, expected_type) in [
            (7, BulkKind::Filesystem, MessageType::FsResponse),
            (8, BulkKind::Tcp, MessageType::TcpFailed),
        ] {
            queue_bulk_open_rejection(&write_tx, &budget, version, id, kind).unwrap();
            let output = write_rx.try_recv().unwrap();
            assert!(output._lane_permit.is_none());
            let message = decode_frame(output.data.inline().unwrap()).unwrap();
            assert_eq!(message.v, version);
            assert_eq!(message.id, id);
            assert_eq!(message.t, expected_type);
            assert_eq!(message.flags, FLAG_TERMINAL);
        }
    }

    #[derive(Default)]
    struct ShortVectoredWriter {
        bytes: Vec<u8>,
        max_write: usize,
    }

    impl AsyncWrite for ShortVectoredWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let len = buf.len().min(self.max_write);
            self.bytes.extend_from_slice(&buf[..len]);
            Poll::Ready(Ok(len))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let mut remaining = self.max_write;
            let mut written = 0;
            for buf in bufs {
                let len = buf.len().min(remaining);
                self.bytes.extend_from_slice(&buf[..len]);
                written += len;
                remaining -= len;
                if remaining == 0 {
                    break;
                }
            }
            Poll::Ready(Ok(written))
        }
    }
    fn restored_agent(attempt_id: &str) -> RestoredAgentState {
        RestoredAgentState {
            inherited_memory: None,
            external_mount_reports: Vec::new(),
            protocol_generation: microsandbox_protocol::message::PROTOCOL_VERSION,
            ready: Ready {
                boot_time_ns: 11,
                init_time_ns: 22,
                ready_time_ns: 33,
                agent_version: "test-agent".into(),
                workload_transport_barrier_version: Some(WORKLOAD_TRANSPORT_BARRIER_VERSION),
                ..Default::default()
            },
            attempt_id: attempt_id.into(),
            host_input: Default::default(),
            input_credit: Default::default(),
            guest_bulk_bytes_target: 0,
        }
    }

    #[tokio::test]
    async fn restored_workload_thaw_uses_private_attempt_scoped_exchange() {
        // Console capacity is now a byte budget, not a count of queued frames.
        let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
        let sock_path = test_agent_endpoint("restore-thaw");
        let mut relay = AgentRelay::new(&sock_path, Arc::clone(&shared))
            .await
            .unwrap();
        let restored = restored_agent("checkpoint-attempt");
        relay.install_restored_ready(&restored).unwrap();

        let guest_shared = Arc::clone(&shared);
        let guest = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let request = loop {
                if let Some(frame) = guest_shared.rx_ring.pop() {
                    break codec::decode_message_frame(&frame).unwrap();
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "host did not send the private thaw request"
                );
                let _ = guest_shared
                    .rx_wake
                    .wait_timeout(std::time::Duration::from_millis(10));
            };

            assert_eq!(request.id, RESTORE_CONTROL_ID);
            assert_eq!(request.t, MessageType::WorkloadThaw);
            assert_eq!(
                request.payload::<WorkloadThaw>().unwrap().mode,
                microsandbox_protocol::core::WorkloadThawMode::Restore
            );
            assert_eq!(
                request.payload::<WorkloadThaw>().unwrap().attempt_id,
                "checkpoint-attempt"
            );

            let mut response = Message::with_payload(
                MessageType::WorkloadThawed,
                RESTORE_CONTROL_ID,
                &WorkloadThawed {
                    attempt_id: "checkpoint-attempt".into(),
                },
            )
            .unwrap();
            response.v = request.v;
            let mut frame = Vec::new();
            codec::encode_to_buf(
                &Message::with_payload(
                    MessageType::WorkloadTransportCredit,
                    RESTORE_CONTROL_ID,
                    &microsandbox_protocol::core::WorkloadTransportCredit {
                        control_bytes: 100,
                        control_frames: 1,
                        ..Default::default()
                    },
                )
                .unwrap(),
                &mut frame,
            )
            .unwrap();
            codec::encode_to_buf(&response, &mut frame).unwrap();
            guest_shared.tx_ring.push(frame).unwrap();
            guest_shared.tx_wake.wake();
        });

        relay.thaw_restored_workload(&restored).unwrap();
        guest.join().unwrap();
        assert!(shared.workload_control.admit(false, 100).unwrap());
        assert!(!shared.workload_control.admit(false, 1).unwrap());
    }

    #[tokio::test]
    async fn restored_ready_preserves_captured_agent_identity() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(8));
        let sock_path = test_agent_endpoint("restore-ready");
        let mut relay = AgentRelay::new(&sock_path, shared).await.unwrap();
        let restored = restored_agent("ready-attempt");

        relay.install_restored_ready(&restored).unwrap();

        let message = codec::decode_message_frame(relay.ready_frame.as_ref().unwrap()).unwrap();
        let ready = message.payload::<Ready>().unwrap();
        assert_eq!(message.v, restored.protocol_generation);
        assert_eq!(message.t, MessageType::Ready);
        assert_eq!(ready.boot_time_ns, 11);
        assert_eq!(ready.init_time_ns, 22);
        assert_eq!(ready.ready_time_ns, 33);
        assert_eq!(ready.agent_version, "test-agent");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn restored_relay_defers_public_endpoint_binding() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(8));
        let sock_path = test_agent_endpoint("restore-deferred-endpoint");
        let mut relay = AgentRelay::new_deferred(&sock_path, shared, None);

        assert!(!sock_path.exists());
        relay.bind_public_endpoint().unwrap();
        assert!(sock_path.exists());

        relay.listener.as_ref().unwrap().cleanup(&sock_path);
    }

    #[test]
    fn restore_bulk_drain_preserves_every_fragmented_tail() {
        let record = microsandbox_protocol::bulk::BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from_static(b"captured bulk"),
        };
        let mut wire = vec![0x51; CLIENT_INCARNATION_SIZE];
        codec::encode_bulk_to_buf(&record, &mut wire).unwrap();
        for split in 0..wire.len() {
            let shared = ConsoleSharedState::with_capacity(4096);
            let mut input = BytesMut::new();
            if split != 0 {
                shared.tx_ring.push(wire[..split].to_vec()).unwrap();
            }
            drain_restored_bulk(&shared, &mut input).unwrap();
            assert_eq!(input.as_ref(), &wire[..split]);
            shared.tx_ring.push(wire[split..].to_vec()).unwrap();
            drain_restored_bulk(&shared, &mut input).unwrap();
            assert!(input.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn restored_bulk_suffix_requires_the_source_decoder_prefix() {
        use msb_krun::ConsolePortBackend;

        let record = microsandbox_protocol::bulk::BulkRecord {
            id: 1,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: Bytes::from(vec![0x61; 128]),
        };
        let mut wire = vec![0x51; CLIENT_INCARNATION_SIZE];
        codec::encode_bulk_to_buf(&record, &mut wire).unwrap();
        let split = wire.len() - 64;
        let source = Arc::new(ConsoleSharedState::with_capacity(4096));
        let source_backend = crate::runner::console::AgentConsoleBackend::new(source.clone());
        let mut source_input = BytesMut::new();
        assert_eq!(source_backend.write(&wire[..split]).unwrap(), split);
        drain_restored_bulk(&source, &mut source_input).unwrap();
        assert_eq!(source_input.as_ref(), &wire[..split]);

        // Model a cut after the source host consumed this prefix. The VMM console state does
        // not serialize the backend queue or this reader buffer, and the resumed guest writer
        // can still have the suffix pending. A fresh destination therefore starts mid-record.
        let destination = Arc::new(ConsoleSharedState::with_capacity(4096));
        let destination_backend =
            crate::runner::console::AgentConsoleBackend::new(destination.clone());
        destination_backend.write(&wire[split..]).unwrap();
        let error = drain_restored_bulk(&destination, &mut BytesMut::new()).unwrap_err();
        assert!(error.to_string().contains("restored bulk framing"));

        // This is missing state, not malformed producer bytes: keeping the exact prefix makes
        // the same suffix decode normally. A VM-level cut test must establish which boundary
        // the freeze handshake guarantees before treating a fresh decoder as safe.
        source_backend.write(&wire[split..]).unwrap();
        drain_restored_bulk(&source, &mut source_input).unwrap();
        assert!(source_input.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn restored_control_suffix_requires_the_source_decoder_prefix() {
        use msb_krun::ConsolePortBackend;

        let wire = encoded_message_id(
            MessageType::ExecStdout,
            1,
            &microsandbox_protocol::exec::ExecStdout {
                data: vec![0x61; 128],
            },
        );
        let split = wire.len() - 64;
        let source = Arc::new(ConsoleSharedState::with_capacity(4096));
        let backend = crate::runner::console::AgentConsoleBackend::new(source.clone());
        backend.write(&wire[..split]).unwrap();
        let mut source_input = BytesMut::from(source.tx_ring.pop().unwrap().as_ref());
        assert!(
            codec::try_decode_frame_from_bytes(&mut source_input)
                .unwrap()
                .is_none()
        );

        let destination = Arc::new(ConsoleSharedState::with_capacity(4096));
        let backend = crate::runner::console::AgentConsoleBackend::new(destination.clone());
        backend.write(&wire[split..]).unwrap();
        let suffix = destination.tx_ring.pop().unwrap();
        assert!(codec::try_decode_frame_from_bytes(&mut BytesMut::from(suffix.as_ref())).is_err());
        source_input.extend_from_slice(suffix.as_ref());
        assert!(
            codec::try_decode_frame_from_bytes(&mut source_input)
                .unwrap()
                .is_some()
        );
        assert!(source_input.is_empty());
    }

    #[tokio::test]
    async fn restore_thaw_drains_backpressured_bulk_before_acknowledgement() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
        let bulk = Arc::new(ConsoleSharedState::with_capacity(256));
        let path = test_agent_endpoint("restore-bulk-pressure");
        let mut relay = AgentRelay::new_deferred(&path, shared.clone(), Some(bulk.clone()));
        let guest = std::thread::spawn(move || {
            let deadline = Instant::now() + std::time::Duration::from_secs(3);
            while shared.rx_ring.pop().is_none() {
                assert!(Instant::now() < deadline);
                let _ = shared
                    .rx_wake
                    .wait_timeout(std::time::Duration::from_millis(1));
            }
            let record = microsandbox_protocol::bulk::BulkRecord {
                id: 1,
                kind: BulkKind::Filesystem,
                flow: BulkFlow::GuestToHost,
                offset: 0,
                payload: Bytes::from(vec![0x61; 128]),
            };
            let mut wire = vec![0x52; CLIENT_INCARNATION_SIZE];
            codec::encode_bulk_to_buf(&record, &mut wire).unwrap();
            // A reset cannot finish if the host leaves old records blocking the bulk port.
            for _ in 0..32 {
                let mut bytes = Bytes::from(wire.clone());
                loop {
                    match bulk.tx_ring.push(bytes) {
                        Ok(()) => {
                            bulk.tx_wake.wake();
                            break;
                        }
                        Err(returned) => {
                            bytes = returned;
                            assert!(Instant::now() < deadline, "restore stopped draining bulk");
                            let _ = bulk
                                .tx_capacity_wake
                                .wait_timeout(std::time::Duration::from_millis(1));
                        }
                    }
                }
            }
            let mut response =
                microsandbox_protocol::transport::encode_relay_client_disconnected_ack(
                    RelayClientDisconnectedAck {
                        id_start: 1,
                        id_end_exclusive: microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP,
                        incarnation: [0x53; CLIENT_INCARNATION_SIZE],
                    },
                )
                .to_vec();
            let ack = Message::with_payload(
                MessageType::WorkloadThawed,
                RESTORE_CONTROL_ID,
                &WorkloadThawed {
                    attempt_id: "bulk-cut".into(),
                },
            )
            .unwrap();
            codec::encode_to_buf(&ack, &mut response).unwrap();
            let tail =
                encoded_message_id(MessageType::Pong, 99, &microsandbox_protocol::core::Pong {});
            response.extend_from_slice(&tail);
            shared.tx_ring.push(response).unwrap();
            shared.tx_wake.wake();
            tail
        });
        relay
            .thaw_restored_workload(&restored_agent("bulk-cut"))
            .unwrap();
        assert_eq!(relay.restored_input.control.as_ref(), guest.join().unwrap());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn restored_lane_reader_consumes_initial_frame_without_another_write() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(4096));
        let (sender, mut receiver) = mpsc::channel(4);
        let frame = encoded_message_id(MessageType::Pong, 1, &microsandbox_protocol::core::Pong {});
        let reader = tokio::spawn(lane_reader_task(
            BytesMut::from(frame.as_slice()),
            Arc::clone(&shared),
            GuestLane::Control,
            false,
            false,
            sender,
            Arc::new(Semaphore::new(4096)),
            Arc::clone(&shared.workload_control),
        ));
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, LaneEvent::Frame(_)));
        reader.abort();
        let _ = reader.await;
    }

    #[test]
    fn restore_activation_record_replaces_prepared_state_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let generation = [0xabu8; 16];

        persist_restore_activation(directory.path(), "attempt-7", generation, "prepared").unwrap();
        persist_restore_activation(directory.path(), "attempt-7", generation, "activated").unwrap();

        let value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("restore-activation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(value["attempt_id"], "attempt-7");
        assert_eq!(value["vm_generation_id"], hex::encode(generation));
        assert_eq!(value["state"], "activated");
        assert_eq!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
                .count(),
            0,
            "atomic publication must not leave temporary activation records"
        );
    }

    fn workload_test_shared(capacity: usize, dual_port: bool) -> Arc<ConsoleSharedState> {
        let shared = Arc::new(ConsoleSharedState::with_capacity(capacity));
        shared.workload_control.install_ready(
            9,
            Ready {
                workload_transport_barrier_version: Some(WORKLOAD_TRANSPORT_BARRIER_VERSION),
                ..Default::default()
            },
            dual_port,
        );
        shared
    }

    async fn next_host_fragment(shared: &ConsoleSharedState) -> Bytes {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(bytes) = shared.rx_ring.pop() {
                    let bytes = Bytes::copy_from_slice(&bytes);
                    shared.rx_capacity_wake.wake();
                    return bytes;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("host writer made no progress")
    }

    #[tokio::test]
    async fn workload_restored_payload_debt_allows_fresh_lease_and_exec() {
        use microsandbox_protocol::core::{
            WORKLOAD_TRANSPORT_BULK_BYTES, WORKLOAD_TRANSPORT_BULK_FRAMES,
            WORKLOAD_TRANSPORT_CONTROL_BYTES, WORKLOAD_TRANSPORT_CONTROL_FRAMES,
            WorkloadTransportCredit, WorkloadTransportPosition,
        };
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        // The inherited stdin remains unconsumed in guest RAM. Its cumulative debt must not be
        // forgiven just to make a new lease/exec usable on the restored host's empty queue.
        let position = WorkloadTransportPosition {
            bulk_bytes: WORKLOAD_TRANSPORT_BULK_BYTES,
            bulk_frames: WORKLOAD_TRANSPORT_BULK_FRAMES,
            ..Default::default()
        };
        let mut credit = WorkloadTransportCredit {
            control_bytes: WORKLOAD_TRANSPORT_CONTROL_BYTES,
            control_frames: WORKLOAD_TRANSPORT_CONTROL_FRAMES,
            bulk_bytes: position.bulk_bytes,
            bulk_frames: position.bulk_frames,
        };
        control.restore(position, credit, 0).unwrap();
        let (tx, rx) = ControlWriter::new();
        let stdin = Bytes::from(encoded_message_id(
            MessageType::ExecStdin,
            1,
            &microsandbox_protocol::exec::ExecStdin {
                data: b"retained".to_vec(),
            },
        ));
        let eof = Bytes::from(encoded_message_id(
            MessageType::ExecStdin,
            1,
            &microsandbox_protocol::exec::ExecStdin { data: Vec::new() },
        ));
        tx.send(ControlWrite::ordinary(stdin.clone(), 1, true))
            .await
            .unwrap();
        tx.send(ControlWrite::ordinary(eof.clone(), 1, true))
            .await
            .unwrap();
        let finish = Bytes::from(encoded_message_id(MessageType::BulkFinish, 1, &()));
        tx.send(ControlWrite::ordinary(finish.clone(), 1, false))
            .await
            .unwrap();
        send_relay_client_connected(&tx, 100, 200, TEST_INCARNATION)
            .await
            .unwrap();
        let exec = Bytes::from(encoded_message_id(MessageType::ExecRequest, 100, &()));
        tx.send(ControlWrite::ordinary(exec.clone(), 100, false))
            .await
            .unwrap();
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        assert_eq!(
            next_host_fragment(&shared).await.as_ref(),
            encode_relay_client_connected(RelayClientConnected {
                id_start: 100,
                id_end_exclusive: 200,
                incarnation: TEST_INCARNATION,
            })
        );
        assert_eq!(next_host_fragment(&shared).await, exec);
        assert!(shared.rx_ring.pop().is_none());
        let gate = control.gate();
        let parked = control.parked_position().await.unwrap();
        assert_eq!(parked.bulk_bytes, position.bulk_bytes);
        assert_eq!(parked.bulk_frames, position.bulk_frames);
        credit.bulk_bytes += (stdin.len() + eof.len()) as u64;
        credit.bulk_frames += 2;
        control.update_credit(credit).unwrap();
        assert!(shared.rx_ring.pop().is_none());
        gate.release();
        // Same-correlation metadata remains behind both bytes and EOF despite spare control credit.
        assert_eq!(next_host_fragment(&shared).await, stdin);
        assert_eq!(next_host_fragment(&shared).await, eof);
        assert_eq!(next_host_fragment(&shared).await, finish);
        drop(tx);
        writer.await.unwrap().unwrap();
    }

    #[test]
    fn workload_metadata_scheduler_preserves_client_and_global_fences() {
        use microsandbox_protocol::core::{WorkloadTransportCredit, WorkloadTransportPosition};
        let shared = workload_test_shared(4096, false);
        let control = &shared.workload_control;
        control
            .restore(
                WorkloadTransportPosition::default(),
                WorkloadTransportCredit {
                    control_bytes: 4096,
                    control_frames: 16,
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        let frame = Bytes::from_static(b"fence");
        let mut pending = VecDeque::from([
            ControlWrite::ordinary(frame.clone(), 101, true),
            ControlWrite::client_fence(frame.clone(), 100, 200),
            ControlWrite::ordinary(frame.clone(), 102, false),
            ControlWrite::ordinary(frame.clone(), 201, false),
            ControlWrite::from(frame.clone()),
            ControlWrite::ordinary(frame, 301, false),
        ]);
        assert!(matches!(
            next_control_write(&mut pending, control)
                .unwrap()
                .unwrap()
                .order,
            ControlOrder::Correlation(201)
        ));
        assert!(next_control_write(&mut pending, control).unwrap().is_none());
        assert_eq!(pending.len(), 5);
    }

    #[tokio::test]
    async fn workload_maintenance_clock_and_cleanup_do_not_fence_unrelated_clients() {
        use microsandbox_protocol::core::{
            ClockSync, WorkloadTransportCredit, WorkloadTransportPosition,
        };
        let shared = workload_test_shared(4096, false);
        let control = &shared.workload_control;
        let mut credit = WorkloadTransportCredit {
            control_bytes: 4096,
            control_frames: 16,
            ..Default::default()
        };
        control
            .restore(WorkloadTransportPosition::default(), credit, 0)
            .unwrap();
        let (tx, rx) = ControlWriter::new();
        let stdin = Bytes::from(encoded_message_id(MessageType::ExecStdin, 1, &()));
        let kill = Bytes::from(encoded_message_id(
            MessageType::ExecSignal,
            101,
            &ExecSignal { signal: 9 },
        ));
        let same_flow_kill = Bytes::from(encoded_message_id(
            MessageType::ExecSignal,
            1,
            &ExecSignal { signal: 9 },
        ));
        let exec = Bytes::from(encoded_message_id(MessageType::ExecRequest, 201, &()));
        tx.send(ControlWrite::ordinary(stdin.clone(), 1, true))
            .await
            .unwrap();
        tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();
        tx.send(ControlWrite::ordinary(kill.clone(), 101, false))
            .await
            .unwrap();
        tx.send(ControlWrite::ordinary(same_flow_kill.clone(), 1, false))
            .await
            .unwrap();
        send_relay_client_connected(&tx, 200, 300, TEST_INCARNATION)
            .await
            .unwrap();
        tx.send(ControlWrite::ordinary(exec.clone(), 201, false))
            .await
            .unwrap();
        tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));

        let first_clock = decode_frame(&next_host_fragment(&shared).await).unwrap();
        assert_eq!(first_clock.t, MessageType::ClockSync);
        assert_eq!(next_host_fragment(&shared).await, kill);
        assert_eq!(
            next_host_fragment(&shared).await.as_ref(),
            encode_relay_client_connected(RelayClientConnected {
                id_start: 200,
                id_end_exclusive: 300,
                incarnation: TEST_INCARNATION,
            })
        );
        assert_eq!(next_host_fragment(&shared).await, exec);
        let second_clock = decode_frame(&next_host_fragment(&shared).await).unwrap();
        assert_eq!(second_clock.t, MessageType::ClockSync);
        assert!(
            second_clock.payload::<ClockSync>().unwrap().unix_time_nanos
                >= first_clock.payload::<ClockSync>().unwrap().unix_time_nanos
        );
        let gate = control.gate();
        let position = control.parked_position().await.unwrap();
        assert_eq!(
            position.bulk_frames, 0,
            "no blocked data was discarded or admitted"
        );
        assert!(shared.rx_ring.pop().is_none());
        credit.bulk_bytes = stdin.len() as u64;
        credit.bulk_frames = 1;
        control.update_credit(credit).unwrap();
        gate.release();
        assert_eq!(next_host_fragment(&shared).await, stdin);
        assert_eq!(next_host_fragment(&shared).await, same_flow_kill);
        drop(tx);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn workload_maintenance_clock_stays_behind_global_lifecycle_fence() {
        use microsandbox_protocol::core::{WorkloadTransportCredit, WorkloadTransportPosition};
        let shared = workload_test_shared(4096, false);
        let control = &shared.workload_control;
        let mut credit = WorkloadTransportCredit {
            control_bytes: 4096,
            control_frames: 16,
            ..Default::default()
        };
        control
            .restore(WorkloadTransportPosition::default(), credit, 0)
            .unwrap();
        let (tx, rx) = ControlWriter::new();
        let stdin = Bytes::from(encoded_message_id(MessageType::ExecStdin, 1, &()));
        let shutdown = Bytes::from(encoded_message_id(MessageType::Shutdown, 0, &()));
        tx.send(ControlWrite::ordinary(stdin.clone(), 1, true))
            .await
            .unwrap();
        tx.send(shutdown.clone().into()).await.unwrap();
        tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(shared.rx_ring.pop().is_none());
        let gate = control.gate();
        assert_eq!(
            control.parked_position().await.unwrap(),
            WorkloadTransportPosition::default()
        );
        credit.bulk_bytes = stdin.len() as u64;
        credit.bulk_frames = 1;
        control.update_credit(credit).unwrap();
        assert!(
            shared.rx_ring.pop().is_none(),
            "pause still gates maintenance"
        );
        gate.release();
        assert_eq!(next_host_fragment(&shared).await, stdin);
        assert_eq!(next_host_fragment(&shared).await, shutdown);
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::ClockSync
        );
        drop(tx);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn workload_clock_refreshes_after_full_ring_and_pause_without_charging_stale_bytes() {
        use microsandbox_protocol::core::{ClockSync, WorkloadTransportPosition};
        let shared = workload_test_shared(4096, false);
        shared.rx_ring.push(Bytes::from(vec![0; 4096])).unwrap();
        let (tx, rx) = ControlWriter::new();
        tx.send(ControlWrite::clock_sync().unwrap()).await.unwrap();
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let gate = shared.workload_control.gate();
        assert_eq!(
            shared.workload_control.parked_position().await.unwrap(),
            WorkloadTransportPosition::default()
        );
        assert_eq!(next_host_fragment(&shared).await.len(), 4096);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(shared.rx_ring.pop().is_none());
        let not_before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        gate.release();
        let wire = next_host_fragment(&shared).await;
        let clock = decode_frame(&wire).unwrap().payload::<ClockSync>().unwrap();
        assert!(
            clock.unix_time_nanos >= not_before,
            "queued clock age must not cross pause"
        );
        let gate = shared.workload_control.gate();
        let position = shared.workload_control.parked_position().await.unwrap();
        assert_eq!(position.control_bytes, wire.len() as u64);
        assert_eq!(position.control_frames, 1);
        assert_eq!(
            tx.control_bytes.available_permits(),
            AGENT_WRITE_CONTROL_BYTES
        );
        gate.release();
        drop(tx);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn workload_clock_credit_uses_actual_cbor_width_not_reserved_maximum() {
        use microsandbox_protocol::core::{
            ClockSync, WorkloadTransportCredit, WorkloadTransportPosition,
        };
        for timestamp in [0, u32::MAX as u64, u64::MAX] {
            let shared = workload_test_shared(4096, false);
            let frame = crate::clock::encode_clock_sync_frame(timestamp).unwrap();
            shared
                .workload_control
                .restore(
                    WorkloadTransportPosition::default(),
                    WorkloadTransportCredit {
                        control_bytes: frame.len() as u64,
                        control_frames: 1,
                        ..Default::default()
                    },
                    0,
                )
                .unwrap();
            let (tx, mut rx) = ControlWriter::new();
            let queued = ControlWrite::clock_sync().unwrap();
            let reservation = queued.data.len();
            assert!(reservation >= frame.len());
            tx.send(queued).await.unwrap();
            let mut write = rx.recv().await.unwrap();
            assert_eq!(
                tx.control_bytes.available_permits(),
                AGENT_WRITE_CONTROL_BYTES - reservation
            );
            assert!(
                admit_control_write(
                    &mut write,
                    &shared.workload_control,
                    Some(&shared),
                    &mut false,
                    || crate::clock::encode_clock_sync_frame(timestamp)
                )
                .unwrap()
            );
            assert_eq!(write.data, frame);
            assert_eq!(
                decode_frame(&write.data)
                    .unwrap()
                    .payload::<ClockSync>()
                    .unwrap()
                    .unix_time_nanos,
                timestamp
            );
            assert!(!shared.workload_control.admit(false, 1).unwrap());
            drop(write);
            assert_eq!(
                tx.control_bytes.available_permits(),
                AGENT_WRITE_CONTROL_BYTES
            );
        }
    }

    fn ordered_tcp_metadata<T: serde::Serialize>(kind: MessageType, payload: &T) -> ControlWrite {
        let message = Message::with_payload(kind, 17, payload).unwrap();
        let mut encoded = Vec::new();
        codec::encode_to_buf(&message, &mut encoded).unwrap();
        let mut write = ControlWrite::ordinary(Bytes::from(encoded), 17, false);
        write.classify_tcp_order(17, None, Some(&message));
        write
    }

    fn ordered_tcp_input() -> ControlWrite {
        let record = microsandbox_protocol::bulk::BulkRecord {
            id: 17,
            kind: BulkKind::Tcp,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from_static(b"request tail"),
        };
        let mut encoded = Vec::new();
        codec::encode_bulk_to_buf(&record, &mut encoded).unwrap();
        let mut write = ControlWrite::ordinary(Bytes::from(encoded), 17, true);
        write.classify_tcp_order(17, Some(bulk_wire_metadata(&write.data).unwrap()), None);
        write
    }

    fn tcp_input_finish() -> ControlWrite {
        ordered_tcp_metadata(
            MessageType::BulkFinish,
            &BulkFinish {
                kind: BulkKind::Tcp,
                flow: BulkFlow::HostToGuest,
                final_offset: b"request tail".len() as u64,
            },
        )
    }

    fn tcp_output_credit() -> ControlWrite {
        ordered_tcp_metadata(
            MessageType::BulkCredit,
            &BulkCredit {
                kind: BulkKind::Tcp,
                flow: BulkFlow::GuestToHost,
                consumed_offset: 0,
                credit_limit: microsandbox_protocol::bulk::DEFAULT_BULK_WINDOW,
            },
        )
    }

    #[test]
    fn workload_combined_tcp_credit_passes_blocked_input_and_finish_only() {
        use microsandbox_protocol::core::{WorkloadTransportCredit, WorkloadTransportPosition};
        let shared = workload_test_shared(4096, false);
        let control = &shared.workload_control;
        let mut credit = WorkloadTransportCredit {
            control_bytes: 4096,
            control_frames: 16,
            ..Default::default()
        };
        control
            .restore(WorkloadTransportPosition::default(), credit, 0)
            .unwrap();
        let input = ordered_tcp_input();
        let input_bytes = input.data.clone();
        let finish = tcp_input_finish();
        let finish_bytes = finish.data.clone();
        let mut pending = VecDeque::from([input, finish, tcp_output_credit()]);
        let gate = control.gate();
        assert!(next_control_write(&mut pending, control).unwrap().is_none());
        gate.release();
        let returned = next_control_write(&mut pending, control).unwrap().unwrap();
        assert!(matches!(returned.order, ControlOrder::TcpOutputCredit(17)));
        assert_eq!(pending.len(), 2);
        assert!(next_control_write(&mut pending, control).unwrap().is_none());
        credit.bulk_bytes = input_bytes.len() as u64;
        credit.bulk_frames = 1;
        control.update_credit(credit).unwrap();
        assert_eq!(
            next_control_write(&mut pending, control)
                .unwrap()
                .unwrap()
                .data,
            input_bytes
        );
        assert_eq!(
            next_control_write(&mut pending, control)
                .unwrap()
                .unwrap()
                .data,
            finish_bytes
        );
        assert!(pending.is_empty());

        // With input capacity available, the new exception does not turn credit into priority.
        let shared = workload_test_shared(4096, false);
        let mut pending =
            VecDeque::from([ordered_tcp_input(), tcp_input_finish(), tcp_output_credit()]);
        for expected in [
            ControlOrder::TcpInputData(17),
            ControlOrder::TcpInputFinish(17),
            ControlOrder::TcpOutputCredit(17),
        ] {
            let actual = next_control_write(&mut pending, &shared.workload_control)
                .unwrap()
                .unwrap()
                .order;
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }
    }

    #[test]
    fn workload_combined_tcp_credit_never_crosses_control_or_owner_fences() {
        use microsandbox_protocol::core::{WorkloadTransportCredit, WorkloadTransportPosition};
        let shared = workload_test_shared(4096, false);
        let control = &shared.workload_control;
        control
            .restore(
                WorkloadTransportPosition::default(),
                WorkloadTransportCredit {
                    control_bytes: 4096,
                    control_frames: 16,
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        for fence in [
            ordered_tcp_metadata(MessageType::BulkCancel, &()),
            ordered_tcp_metadata(MessageType::TcpConnect, &()),
            ordered_tcp_metadata(MessageType::Ping, &()),
            ControlWrite::client_fence(Bytes::new(), 1, 100),
            ControlWrite::from(Bytes::new()),
        ] {
            let mut pending = VecDeque::from([ordered_tcp_input(), fence, tcp_output_credit()]);
            assert!(next_control_write(&mut pending, control).unwrap().is_none());
            assert_eq!(pending.len(), 3);
        }
        let valid = BulkCredit {
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            consumed_offset: 0,
            credit_limit: microsandbox_protocol::bulk::DEFAULT_BULK_WINDOW,
        };
        for payload in [
            BulkCredit {
                kind: BulkKind::Filesystem,
                ..valid
            },
            BulkCredit {
                flow: BulkFlow::HostToGuest,
                ..valid
            },
            BulkCredit {
                consumed_offset: 2,
                credit_limit: 1,
                ..valid
            },
            BulkCredit {
                credit_limit: MAX_BULK_WINDOW + 1,
                ..valid
            },
        ] {
            let mut pending = VecDeque::from([
                ordered_tcp_input(),
                ordered_tcp_metadata(MessageType::BulkCredit, &payload),
            ]);
            assert!(next_control_write(&mut pending, control).unwrap().is_none());
        }
        let mut pending = VecDeque::from([
            ordered_tcp_input(),
            ordered_tcp_metadata(MessageType::BulkCredit, &()),
        ]);
        assert!(next_control_write(&mut pending, control).unwrap().is_none());
        // The exclusive raw flag is not sufficient: only previously validated TCP input gets
        // the exception. Filesystem or reverse-direction raw metadata retains strict ordering.
        for (kind, flow) in [
            (BulkKind::Filesystem, BulkFlow::HostToGuest),
            (BulkKind::Tcp, BulkFlow::GuestToHost),
        ] {
            let mut input = ControlWrite::ordinary(ordered_tcp_input().data, 17, true);
            input.classify_tcp_order(17, Some((kind, flow, 0, 12)), None);
            let mut pending = VecDeque::from([input, tcp_output_credit()]);
            assert!(next_control_write(&mut pending, control).unwrap().is_none());
        }
        // Only the correctly directed TCP finish commutes; unknown/malformed metadata remains a fence.
        for finish in [
            BulkFinish {
                kind: BulkKind::Tcp,
                flow: BulkFlow::GuestToHost,
                final_offset: 0,
            },
            BulkFinish {
                kind: BulkKind::Filesystem,
                flow: BulkFlow::HostToGuest,
                final_offset: 0,
            },
        ] {
            let mut pending = VecDeque::from([
                ordered_tcp_input(),
                ordered_tcp_metadata(MessageType::BulkFinish, &finish),
                tcp_output_credit(),
            ]);
            assert!(next_control_write(&mut pending, control).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn workload_class_reservations_bound_pending_bytes_and_frames() {
        let (tx, mut rx) = ControlWriter::new();
        let data = Bytes::from(vec![0; AGENT_WRITE_DATA_BYTES / AGENT_WRITE_CLASS_FRAMES]);
        let metadata = Bytes::from(vec![
            0;
            AGENT_WRITE_CONTROL_BYTES / AGENT_WRITE_CLASS_FRAMES
        ]);
        let mut pending = Vec::new();
        for id in 1..=AGENT_WRITE_CLASS_FRAMES as u32 {
            tx.try_send(ControlWrite::ordinary(data.clone(), id, true))
                .unwrap();
            pending.push(rx.recv().await.unwrap());
        }
        assert_eq!(tx.data_bytes.available_permits(), 0);
        assert_eq!(tx.data_frames.available_permits(), 0);
        assert!(matches!(
            tx.try_send(ControlWrite::ordinary(Bytes::new(), 99, true)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        for id in 100..100 + AGENT_WRITE_CLASS_FRAMES as u32 {
            tx.try_send(ControlWrite::ordinary(metadata.clone(), id, false))
                .unwrap();
            pending.push(rx.recv().await.unwrap());
        }
        assert_eq!(pending.len(), AGENT_WRITE_CHANNEL_CAPACITY);
        assert_eq!(tx.control_bytes.available_permits(), 0);
        assert_eq!(tx.control_frames.available_permits(), 0);
        assert!(matches!(
            tx.try_send(ControlWrite::ordinary(Bytes::new(), 999, false)),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        drop(pending);
        assert_eq!(tx.data_bytes.available_permits(), AGENT_WRITE_DATA_BYTES);
        assert_eq!(
            tx.control_bytes.available_permits(),
            AGENT_WRITE_CONTROL_BYTES
        );
        assert_eq!(tx.data_frames.available_permits(), AGENT_WRITE_CLASS_FRAMES);
        assert_eq!(
            tx.control_frames.available_permits(),
            AGENT_WRITE_CLASS_FRAMES
        );
    }

    #[tokio::test]
    async fn workload_reservation_waiters_cancel_and_wake_on_receiver_close() {
        let (tx, mut rx) = ControlWriter::new();
        let mut retained = Vec::new();
        for id in 1..=AGENT_WRITE_CLASS_FRAMES as u32 {
            tx.send(ControlWrite::ordinary(Bytes::new(), id, true))
                .await
                .unwrap();
            retained.push(rx.recv().await.unwrap());
        }
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                tx.send(ControlWrite::ordinary(Bytes::new(), 99, true))
            )
            .await
            .is_err()
        );
        assert_eq!(tx.data_frames.available_permits(), 0);
        let sender = tx.clone();
        let waiting = tokio::spawn(async move {
            sender
                .send(ControlWrite::ordinary(Bytes::new(), 100, true))
                .await
        });
        drop(rx);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        drop(retained);
        assert_eq!(tx.data_frames.available_permits(), AGENT_WRITE_CLASS_FRAMES);
    }

    #[tokio::test]
    async fn workload_private_freeze_bypasses_both_full_admission_classes() {
        use microsandbox_protocol::core::{
            WorkloadFreeze, WorkloadFrozen, WorkloadTransportCredit, WorkloadTransportPosition,
        };
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        control
            .restore(
                WorkloadTransportPosition::default(),
                WorkloadTransportCredit::default(),
                0,
            )
            .unwrap();
        let gate = control.gate();
        let (tx, rx) = ControlWriter::new();
        let mut expected = Vec::new();
        for uses_data_credit in [true, false] {
            for id in 1..=AGENT_WRITE_CLASS_FRAMES as u32 {
                let kind = if uses_data_credit {
                    MessageType::ExecStdin
                } else {
                    MessageType::Ping
                };
                let bytes = Bytes::from(encoded_message_id(kind, id, &()));
                tx.send(ControlWrite::ordinary(bytes.clone(), id, uses_data_credit))
                    .await
                    .unwrap();
                expected.push(bytes);
            }
        }
        assert_eq!(tx.data_frames.available_permits(), 0);
        assert_eq!(tx.control_frames.available_permits(), 0);
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        let position = tokio::time::timeout(Duration::from_secs(1), control.parked_position())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(position, WorkloadTransportPosition::default());
        let requester = Arc::clone(&control);
        let request = tokio::spawn(async move {
            requester
                .request(
                    Message::with_payload(
                        MessageType::WorkloadFreeze,
                        0,
                        &WorkloadFreeze {
                            external_mount_tags: Vec::new(),
                            attempt_id: "full-classes".into(),
                            host_input: position,
                        },
                    )
                    .unwrap(),
                    "full-classes",
                )
                .await
        });
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::WorkloadFreeze
        );
        assert!(shared.rx_ring.pop().is_none());
        control
            .reply(
                Message::with_payload(
                    MessageType::WorkloadFrozen,
                    WORKLOAD_CONTROL_ID,
                    &WorkloadFrozen {
                        external_mounts_synced: false,
                        attempt_id: "full-classes".into(),
                        guest_bulk_bytes_target: 0,
                        input_credit: WorkloadTransportCredit::default(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        request.await.unwrap().unwrap();
        control
            .update_credit(WorkloadTransportCredit {
                control_bytes: 4096,
                control_frames: AGENT_WRITE_CLASS_FRAMES as u64,
                bulk_bytes: 4096,
                bulk_frames: AGENT_WRITE_CLASS_FRAMES as u64,
            })
            .unwrap();
        gate.release();
        for frame in expected {
            assert_eq!(next_host_fragment(&shared).await, frame);
        }
        assert_eq!(tx.data_frames.available_permits(), AGENT_WRITE_CLASS_FRAMES);
        assert_eq!(
            tx.control_frames.available_permits(),
            AGENT_WRITE_CLASS_FRAMES
        );
        drop(tx);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn workload_gate_keeps_source_fifo_until_confirmed_continue() {
        use microsandbox_protocol::core::{
            WorkloadFreeze, WorkloadFrozen, WorkloadTransportCredit, WorkloadTransportPosition,
        };
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        // Model a live guest whose previously admitted input still occupies the whole window.
        control
            .restore(
                WorkloadTransportPosition::default(),
                WorkloadTransportCredit::default(),
                0,
            )
            .unwrap();
        let (tx, rx) = mpsc::channel(2);
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        let first = Bytes::from(encoded_message_id(
            MessageType::Ping,
            1,
            &microsandbox_protocol::core::Ping {},
        ));
        let second = Bytes::from(encoded_message_id(
            MessageType::Ping,
            2,
            &microsandbox_protocol::core::Ping {},
        ));
        let (done, mut completed) = oneshot::channel();
        tx.send(ControlWrite {
            completion: Some(done),
            ..first.clone().into()
        })
        .await
        .unwrap();
        tx.send(second.clone().into()).await.unwrap();
        let gate = control.gate();
        let position =
            tokio::time::timeout(std::time::Duration::from_secs(1), control.parked_position())
                .await
                .unwrap()
                .unwrap();
        assert!(shared.rx_ring.pop().is_none());
        assert!(completed.try_recv().is_err());
        let request = Message::with_payload(
            MessageType::WorkloadFreeze,
            0,
            &WorkloadFreeze {
                external_mount_tags: Vec::new(),
                attempt_id: "fifo".into(),
                host_input: position,
            },
        )
        .unwrap();
        let requester = Arc::clone(&control);
        let freeze = tokio::spawn(async move { requester.request(request, "fifo").await });
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::WorkloadFreeze
        );
        control
            .reply(
                Message::with_payload(
                    MessageType::WorkloadFrozen,
                    WORKLOAD_CONTROL_ID,
                    &WorkloadFrozen {
                        external_mounts_synced: false,
                        attempt_id: "fifo".into(),
                        guest_bulk_bytes_target: 0,
                        input_credit: Default::default(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        freeze.await.unwrap().unwrap();
        assert!(
            shared.rx_ring.pop().is_none(),
            "Frozen must not release source input"
        );
        let request = Message::with_payload(
            MessageType::WorkloadThaw,
            0,
            &WorkloadThaw {
                attempt_id: "fifo".into(),
                mode: microsandbox_protocol::core::WorkloadThawMode::Continue,
            },
        )
        .unwrap();
        let requester = Arc::clone(&control);
        let thaw = tokio::spawn(async move { requester.request(request, "fifo").await });
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::WorkloadThaw
        );
        control
            .reply(
                Message::with_payload(
                    MessageType::WorkloadThawed,
                    WORKLOAD_CONTROL_ID,
                    &WorkloadThawed {
                        attempt_id: "fifo".into(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        thaw.await.unwrap().unwrap();
        control
            .update_credit(WorkloadTransportCredit {
                control_bytes: 4096,
                control_frames: 2,
                ..Default::default()
            })
            .unwrap();
        assert!(
            shared.rx_ring.pop().is_none(),
            "credit alone cannot release the gate"
        );
        gate.release();
        assert_eq!(next_host_fragment(&shared).await, first);
        assert_eq!(next_host_fragment(&shared).await, second);
        completed.await.unwrap();
        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test]
    async fn workload_canceled_frozen_and_recovery_thawed_share_one_input_batch() {
        use microsandbox_protocol::core::{WorkloadFreeze, WorkloadFrozen};
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let mut writes = control.start();
        let requester = Arc::clone(&control);
        let freeze = tokio::spawn(async move {
            requester
                .request(
                    Message::with_payload(
                        MessageType::WorkloadFreeze,
                        0,
                        &WorkloadFreeze {
                            external_mount_tags: Vec::new(),
                            attempt_id: "cancel".into(),
                            host_input: Default::default(),
                        },
                    )
                    .unwrap(),
                    "cancel",
                )
                .await
        });
        writes.recv().await.unwrap();
        freeze.abort();
        let _ = freeze.await;
        let requester = Arc::clone(&control);
        let thaw = tokio::spawn(async move {
            requester
                .request(
                    Message::with_payload(
                        MessageType::WorkloadThaw,
                        0,
                        &WorkloadThaw {
                            attempt_id: "cancel".into(),
                            mode: microsandbox_protocol::core::WorkloadThawMode::Continue,
                        },
                    )
                    .unwrap(),
                    "cancel",
                )
                .await
        });
        writes.recv().await.unwrap();
        let mut wire = encoded_message_id(
            MessageType::WorkloadFrozen,
            WORKLOAD_CONTROL_ID,
            &WorkloadFrozen {
                external_mounts_synced: false,
                attempt_id: "cancel".into(),
                guest_bulk_bytes_target: 0,
                input_credit: Default::default(),
            },
        );
        wire.extend_from_slice(&encoded_message_id(
            MessageType::WorkloadThawed,
            WORKLOAD_CONTROL_ID,
            &WorkloadThawed {
                attempt_id: "cancel".into(),
            },
        ));
        let reader = tokio::spawn(combined_ring_reader_task(
            BytesMut::from(wire.as_slice()),
            shared,
            false,
            Arc::new(Mutex::new(HashMap::new())),
            None,
            Arc::new(SessionRegistry::default()),
            Arc::new(Mutex::new(HashMap::new())),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), thaw)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        reader.abort();
        let _ = reader.await;
    }

    #[tokio::test]
    async fn workload_private_reply_bypasses_sdk_output_admission() {
        use microsandbox_protocol::core::{WorkloadFreeze, WorkloadFrozen};
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let mut writes = control.start();
        let requester = Arc::clone(&control);
        let request = tokio::spawn(async move {
            requester
                .request(
                    Message::with_payload(
                        MessageType::WorkloadFreeze,
                        0,
                        &WorkloadFreeze {
                            external_mount_tags: Vec::new(),
                            attempt_id: "private".into(),
                            host_input: Default::default(),
                        },
                    )
                    .unwrap(),
                    "private",
                )
                .await
        });
        writes.recv().await.unwrap();
        let wire = encoded_message_id(
            MessageType::WorkloadFrozen,
            WORKLOAD_CONTROL_ID,
            &WorkloadFrozen {
                external_mounts_synced: false,
                attempt_id: "private".into(),
                guest_bulk_bytes_target: 0,
                input_credit: Default::default(),
            },
        );
        let (events, mut received) = mpsc::channel(1);
        let reader = tokio::spawn(lane_reader_task(
            BytesMut::from(wire.as_slice()),
            shared,
            GuestLane::Control,
            true,
            false,
            events,
            Arc::new(Semaphore::new(0)),
            control,
        ));
        tokio::time::timeout(std::time::Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(received.try_recv().is_err());
        reader.abort();
        let _ = reader.await;
    }

    #[tokio::test]
    async fn workload_bulk_gate_finishes_current_fragmented_record() {
        let shared = workload_test_shared(100, true);
        let control = Arc::clone(&shared.workload_control);
        let (tx, rx) = mpsc::channel(2);
        let budget = Arc::new(Semaphore::new(1024));
        let data = Bytes::from(encoded_host_raw(1, 0, &[0x5a; 64]));
        tx.send(BulkWriterCommand::Write(BulkWrite {
            id: 1,
            incarnation: TEST_INCARNATION,
            flow: BulkFlow::HostToGuest,
            payload_len: 64,
            _permit: Arc::clone(&budget)
                .acquire_many_owned(data.len() as u32)
                .await
                .unwrap(),
            data: BulkWriteData::Inline(data.clone()),
        }))
        .await
        .unwrap();
        let writer = tokio::spawn(bulk_ring_writer_task(
            Arc::clone(&shared),
            rx,
            Arc::clone(&control),
        ));
        let prefix = next_host_fragment(&shared).await;
        assert_eq!(prefix.as_ref(), TEST_INCARNATION);
        let gate = control.gate();
        control.park(false); // This fixture has no ordinary primary writer.
        let position =
            tokio::time::timeout(std::time::Duration::from_secs(1), control.parked_position())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            position.bulk_bytes,
            (CLIENT_INCARNATION_SIZE + data.len()) as u64
        );
        assert_eq!(position.bulk_frames, 1);
        assert_eq!(next_host_fragment(&shared).await, data);
        gate.release();
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), writer)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(budget.available_permits(), 1024);
    }

    #[tokio::test]
    async fn workload_post_ready_shutdown_uses_counted_fifo() {
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let (tx, rx) = ControlWriter::new();
        control.register_ordinary_writer(tx.clone());
        let first = Bytes::from(encoded_message_id(
            MessageType::Ping,
            1,
            &microsandbox_protocol::core::Ping {},
        ));
        tx.send(first.clone().into()).await.unwrap();
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        assert_eq!(next_host_fragment(&shared).await, first);
        let shutdown = encoded_message_id(MessageType::Shutdown, 0, &());
        let shutdown_len = shutdown.len();
        let sender = Arc::clone(&shared);
        tokio::task::spawn_blocking(move || {
            push_guest_frame_until(&sender, shutdown, std::time::Duration::from_secs(1))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::Shutdown
        );
        let gate = control.gate();
        let position =
            tokio::time::timeout(std::time::Duration::from_secs(1), control.parked_position())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(position.control_bytes, (first.len() + shutdown_len) as u64);
        assert_eq!(position.control_frames, 2);
        gate.release();
        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test]
    async fn workload_post_ready_shutdown_respects_gate_and_deadline() {
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let (tx, rx) = ControlWriter::new();
        control.register_ordinary_writer(tx);
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        let gate = control.gate();
        tokio::time::timeout(std::time::Duration::from_secs(1), control.parked_position())
            .await
            .unwrap()
            .unwrap();
        let sender = Arc::clone(&shared);
        let result = tokio::task::spawn_blocking(move || {
            push_guest_frame_until(
                &sender,
                encoded_message_id(MessageType::Shutdown, 0, &()),
                std::time::Duration::from_millis(20),
            )
        })
        .await
        .unwrap();
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(shared.rx_ring.pop().is_none());
        writer.abort();
        let _ = writer.await;
        gate.release();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_shutdown_yields_to_writer_and_preserves_counted_fifo() {
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let (tx, rx) = ControlWriter::new();
        control.register_ordinary_writer(tx.clone());
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        tokio::task::yield_now().await; // Let the real writer register as active.
        let first = Bytes::from(encoded_message_id(MessageType::Ping, 1, &()));
        tx.send(first.clone().into()).await.unwrap();
        let shutdown = encoded_message_id(MessageType::Shutdown, 0, &());
        let expected_bytes = first.len() + shutdown.len();
        let guest_shared = Arc::clone(&shared);
        let guest = tokio::spawn(async move {
            // This small fixture has one physical queue entry. Model guest consumption so
            // the later shutdown can enter that queue without weakening FIFO admission.
            [
                next_host_fragment(&guest_shared).await,
                next_host_fragment(&guest_shared).await,
            ]
        });

        // There is no second worker to rescue a blocking sender. This direct await must let
        // the writer process both the earlier frame and the shutdown's admission receipt.
        push_guest_frame_until_async(&shared, shutdown, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        let [observed_first, observed_shutdown] = guest.await.unwrap();
        assert_eq!(observed_first, first);
        assert_eq!(
            decode_frame(&observed_shutdown).unwrap().t,
            MessageType::Shutdown
        );
        assert!(shared.rx_ring.pop().is_none());
        let gate = control.gate();
        let position = control.parked_position().await.unwrap();
        assert_eq!(position.control_frames, 2);
        assert_eq!(position.control_bytes, expected_bytes as u64);
        gate.release();
        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test]
    async fn async_shutdown_timeout_preserves_gated_accepted_frame() {
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let (tx, rx) = ControlWriter::new();
        control.register_ordinary_writer(tx);
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        let gate = control.gate();
        control.parked_position().await.unwrap();
        let result = push_guest_frame_until_async(
            &shared,
            encoded_message_id(MessageType::Shutdown, 0, &()),
            std::time::Duration::from_millis(20),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(shared.rx_ring.pop().is_none());
        // A caller timing out never retracts accepted input or bypasses a resident pause.
        gate.release();
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::Shutdown
        );
        assert!(shared.rx_ring.pop().is_none());
        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test]
    async fn async_shutdown_waits_for_ring_capacity_not_just_queue_acceptance() {
        let shared = workload_test_shared(128, false);
        let control = Arc::clone(&shared.workload_control);
        let (tx, rx) = ControlWriter::new();
        control.register_ordinary_writer(tx);
        shared.rx_ring.push(Bytes::from(vec![7; 128])).unwrap();
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        tokio::task::yield_now().await;
        let sender = Arc::clone(&shared);
        let delivery = tokio::spawn(async move {
            push_guest_frame_until_async(
                &sender,
                encoded_message_id(MessageType::Shutdown, 0, &()),
                std::time::Duration::from_secs(1),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(!delivery.is_finished(), "queue acceptance is not delivery");
        assert_eq!(next_host_fragment(&shared).await.as_ref(), &[7; 128]);
        delivery.await.unwrap().unwrap();
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::Shutdown
        );
        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test(start_paused = true)]
    async fn async_shutdown_shares_one_deadline_and_releases_unaccepted_permits() {
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let _private = control.start();
        let (tx, mut rx) = ControlWriter::new();
        control.register_ordinary_writer(tx.clone());
        let held = Arc::clone(&tx.control_bytes)
            .acquire_many_owned((AGENT_WRITE_CONTROL_BYTES - 1) as u32)
            .await
            .unwrap();
        let result = push_guest_frame_until_async(
            &shared,
            encoded_message_id(MessageType::Shutdown, 0, &()),
            std::time::Duration::from_millis(10),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert_eq!(
            tx.control_frames.available_permits(),
            AGENT_WRITE_CLASS_FRAMES
        );
        assert_eq!(tx.control_bytes.available_permits(), 1);
        assert!(rx.try_recv().is_err());

        let sender = Arc::clone(&shared);
        let delivery = tokio::spawn(async move {
            push_guest_frame_until_async(
                &sender,
                encoded_message_id(MessageType::Shutdown, 0, &()),
                std::time::Duration::from_millis(40),
            )
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(20)).await;
        drop(held);
        let accepted = rx.recv().await.unwrap();
        assert!(matches!(accepted.order, ControlOrder::GlobalFence));
        tokio::time::advance(std::time::Duration::from_millis(21)).await;
        tokio::task::yield_now().await;
        assert!(
            delivery.is_finished(),
            "receipt wait must not restart the deadline"
        );
        assert!(
            delivery
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        drop(accepted);
        assert_eq!(
            tx.control_frames.available_permits(),
            AGENT_WRITE_CLASS_FRAMES
        );
        assert_eq!(
            tx.control_bytes.available_permits(),
            AGENT_WRITE_CONTROL_BYTES
        );
    }

    #[tokio::test]
    async fn async_shutdown_reports_dropped_receipt_and_receiver() {
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        let _private = control.start();
        let (tx, mut rx) = ControlWriter::new();
        control.register_ordinary_writer(tx);
        let sender = Arc::clone(&shared);
        let delivery = tokio::spawn(async move {
            push_guest_frame_until_async(
                &sender,
                encoded_message_id(MessageType::Shutdown, 0, &()),
                std::time::Duration::from_secs(60),
            )
            .await
        });
        drop(rx.recv().await.unwrap());
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), delivery)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("dropped admission receipt"));
        drop(rx);
        let result = push_guest_frame_until_async(
            &shared,
            encoded_message_id(MessageType::Shutdown, 0, &()),
            std::time::Duration::from_secs(60),
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("writer stopped"));
    }

    #[tokio::test]
    async fn async_shutdown_cancellation_keeps_accepted_frame_behind_credit() {
        use microsandbox_protocol::core::{WorkloadTransportCredit, WorkloadTransportPosition};
        let shared = workload_test_shared(4096, false);
        let control = Arc::clone(&shared.workload_control);
        control
            .restore(
                WorkloadTransportPosition::default(),
                WorkloadTransportCredit::default(),
                0,
            )
            .unwrap();
        let (tx, rx) = ControlWriter::new();
        control.register_ordinary_writer(tx.clone());
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        tokio::task::yield_now().await;
        let sender = Arc::clone(&shared);
        let delivery = tokio::spawn(async move {
            push_guest_frame_until_async(
                &sender,
                encoded_message_id(MessageType::Shutdown, 0, &()),
                std::time::Duration::from_secs(1),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while tx.control_frames.available_permits() == AGENT_WRITE_CLASS_FRAMES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!delivery.is_finished());
        assert!(
            shared.rx_ring.pop().is_none(),
            "shutdown cannot bypass credit"
        );
        delivery.abort();
        let _ = delivery.await;
        control
            .update_credit(WorkloadTransportCredit {
                control_bytes: 4096,
                control_frames: 1,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            decode_frame(&next_host_fragment(&shared).await).unwrap().t,
            MessageType::Shutdown
        );
        assert!(shared.rx_ring.pop().is_none());
        assert_eq!(
            tx.control_frames.available_permits(),
            AGENT_WRITE_CLASS_FRAMES
        );
        writer.abort();
        let _ = writer.await;
    }

    #[tokio::test]
    async fn async_shutdown_ready_without_writer_never_uses_bootstrap_fallback() {
        let shared = workload_test_shared(4096, false);
        let result = push_guest_frame_until_async(
            &shared,
            encoded_message_id(MessageType::Shutdown, 0, &()),
            std::time::Duration::ZERO,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("not running"));
        assert!(shared.rx_ring.pop().is_none());
        let pre_ready = Arc::new(ConsoleSharedState::with_capacity(4096));
        push_guest_frame_until_async(&pre_ready, vec![1, 2, 3], std::time::Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(pre_ready.rx_ring.pop().unwrap().as_ref(), &[1, 2, 3]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_shutdown_bootstrap_backpressure_leaves_guest_consumer_runnable() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(128));
        shared.rx_ring.push(Bytes::from(vec![7; 128])).unwrap();
        let guest_shared = Arc::clone(&shared);
        let guest = tokio::spawn(async move {
            // No writer exists before Ready. Even this fallback must yield the only async
            // worker so a guest-side consumer can release the full bootstrap queue.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            assert_eq!(next_host_fragment(&guest_shared).await.as_ref(), &[7; 128]);
            next_host_fragment(&guest_shared).await
        });
        let shutdown = encoded_message_id(MessageType::Shutdown, 0, &());
        push_guest_frame_until_async(&shared, shutdown.clone(), std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(guest.await.unwrap().as_ref(), shutdown);
        assert!(shared.rx_ring.pop().is_none());
    }

    #[test]
    fn workload_ready_without_writer_never_falls_back_to_direct_input() {
        let shared = workload_test_shared(4096, false);
        assert!(
            push_guest_frame_until(
                &shared,
                encoded_message_id(MessageType::Shutdown, 0, &()),
                std::time::Duration::ZERO
            )
            .unwrap_err()
            .to_string()
            .contains("not running")
        );
        assert!(shared.rx_ring.pop().is_none());
        let pre_ready = ConsoleSharedState::with_capacity(4096);
        push_guest_frame_until(&pre_ready, vec![1, 2, 3], std::time::Duration::ZERO).unwrap();
        assert_eq!(pre_ready.rx_ring.pop().unwrap().as_ref(), &[1, 2, 3]);
    }

    #[tokio::test]
    async fn workload_writer_abort_wakes_pending_lifecycle_request() {
        use microsandbox_protocol::core::WorkloadFreeze;
        let shared = workload_test_shared(4096, false);
        let (tx, rx) = mpsc::channel(1);
        let writer = tokio::spawn(ring_writer_task(Arc::clone(&shared), rx));
        tx.send(
            Bytes::from(encoded_message_id(
                MessageType::Ping,
                1,
                &microsandbox_protocol::core::Ping {},
            ))
            .into(),
        )
        .await
        .unwrap();
        next_host_fragment(&shared).await;
        let control = Arc::clone(&shared.workload_control);
        let request = tokio::spawn(async move {
            control
                .request(
                    Message::with_payload(
                        MessageType::WorkloadFreeze,
                        0,
                        &WorkloadFreeze {
                            external_mount_tags: Vec::new(),
                            attempt_id: "abort".into(),
                            host_input: Default::default(),
                        },
                    )
                    .unwrap(),
                    "abort",
                )
                .await
        });
        next_host_fragment(&shared).await;
        writer.abort();
        let _ = writer.await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), request)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .contains("closed")
        );
    }
}
