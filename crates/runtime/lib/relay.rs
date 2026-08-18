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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Buf, Bytes, BytesMut};
#[cfg(unix)]
use microsandbox_filesystem::{BindIdentityMap, BindIdentityMapHandle};
use microsandbox_protocol::AGENT_RELAY_MAX_CLIENTS;
use microsandbox_protocol::bulk::{
    BULK_FLOW_MASK_GUEST_TO_HOST, BULK_HEADER_SIZE, BulkAccepted, BulkCancel, BulkCancelReason,
    BulkFinish, BulkFlow, BulkKind, MAX_BULK_RECORD_PAYLOAD,
};
use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE, MAX_WIRE_FRAME};
use microsandbox_protocol::core::{InitAck, InitResolved, Ready, RelayClientDisconnected};
use microsandbox_protocol::exec::{ExecRequest, ExecSignal, ExecStderr, ExecStdout};
use microsandbox_protocol::fs::FsRequest;
use microsandbox_protocol::message::{
    FLAG_BULK, FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL, FRAME_HEADER_SIZE, Message,
    MessageType,
};
use microsandbox_protocol::tcp::TcpConnect;
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

use crate::clock::spawn_clock_sync_task;
use crate::console::ConsoleSharedState;
use crate::exec_log::{LogSource, LogWriter};
use crate::{RuntimeError, RuntimeResult};

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

/// At most eight generation-6 frames may wait between clients and the console.
/// Since a frame is capped at 4 MiB, this bounds the channel at 32 MiB.
const AGENT_WRITE_CHANNEL_CAPACITY: usize = 8;

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

    /// Active generation-7 bulk operations that need typed transport-failure cancellation.
    active_bulk: Arc<std::sync::Mutex<HashMap<u32, BulkKind>>>,
    /// Channel for sending frames to this client's writer task.
    /// Using a channel avoids holding the client mutex across async writes.
    /// Uses `Bytes` for zero-copy frame forwarding from the ring buffer.
    write_tx: mpsc::UnboundedSender<ClientWrite>,

    /// Byte admission for this client's nonblocking writer mailbox.
    write_budget: Arc<Semaphore>,

    /// Requests teardown when this client's bounded output path stops making progress.
    disconnect_tx: watch::Sender<bool>,
}

/// One ordered control-lane write, optionally acknowledged after physical ring admission.
pub(crate) struct ControlWrite {
    data: Bytes,
    completion: Option<oneshot::Sender<()>>,
}

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
struct RingReaderContext {
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    log_writer: Option<Arc<LogWriter>>,
    session_registry: Arc<SessionRegistry>,
    pending_disconnects: Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>>,
    bulk_writer: Option<mpsc::Sender<BulkWriterCommand>>,
}

/// A client-bound frame whose aggregate capacity lives until the socket accepts it.
struct ClientWrite {
    data: Bytes,
    /// Aggregate physical-lane admission, retained until the SDK socket consumes the frame.
    _lane_permit: tokio::sync::OwnedSemaphorePermit,
    /// Per-client admission, retained for the same lifetime as the aggregate permit.
    _client_permit: tokio::sync::OwnedSemaphorePermit,
}

/// Nonblocking handles cloned from one live client owner before guest-output routing.
struct ClientRoute {
    write_tx: mpsc::UnboundedSender<ClientWrite>,
    write_budget: Arc<Semaphore>,
    disconnect_tx: watch::Sender<bool>,
}

/// Client-originated raw frame retained until the bulk console ring accepts it.
struct BulkWrite {
    id: u32,
    incarnation: ClientIncarnation,
    data: Bytes,
    /// Validated direction carried from the client boundary.
    flow: BulkFlow,
    /// Validated payload length carried through scheduling to avoid reparsing the wire header.
    payload_len: usize,
    _permit: tokio::sync::OwnedSemaphorePermit,
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

/// Guest-to-host ordering state for one generation-7 bulk correlation.
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
    /// Shared ring buffers + wake pipes for console backend communication.
    shared: Arc<ConsoleSharedState>,
    /// Optional second ring pair dedicated to generation-7 raw records.
    bulk_shared: Option<Arc<ConsoleSharedState>>,
    /// Identity observed and acknowledged on the second physical port.
    bulk_connection_id: Option<[u8; 16]>,
    /// Whether `core.ready` selected the bound dual-port profile.
    dual_port_active: bool,
    /// Whether the relay selected acknowledged correlation-range ownership.
    range_lease_active: bool,
    /// Local IPC listener for client connections.
    listener: AgentListener,
    /// Local IPC endpoint address.
    endpoint: PathBuf,
    /// Cached `core.ready` frame bytes (length-prefixed wire format).
    ready_frame: Option<Vec<u8>>,
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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

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
            bulk_connection_id: None,
            dual_port_active: false,
            range_lease_active: false,
            listener,
            endpoint: agent_sock_path.to_path_buf(),
            ready_frame: None,
            log_writer: None,
            #[cfg(unix)]
            bind_identity_map: None,
            #[cfg(unix)]
            bind_identity_map_mount_count: 0,
        })
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

        let host_owner_uid = unsafe { libc::getuid() as u32 };
        let map = BindIdentityMap::new(
            host_owner_uid,
            resolved.default_user.uid,
            resolved.default_user.gid,
        );

        handle
            .set(map)
            .map_err(|_| RuntimeError::Custom("bind identity map already installed".into()))?;

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
                    self.ready_frame = Some(frame.data.to_vec());
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

        // Shared state: map from client slot index to client state.
        let clients: Arc<Mutex<HashMap<u32, ClientState>>> = Arc::new(Mutex::new(HashMap::new()));

        // Bounded channel for client reader tasks to send frames to the ring writer.
        // Backpressure prevents unbounded memory growth from client floods.
        let (agent_tx, agent_rx) = mpsc::channel::<ControlWrite>(AGENT_WRITE_CHANNEL_CAPACITY);

        // Track which client slots are in use.
        let used_slots: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        // A slot remains in `used_slots` until agentd acknowledges its disconnect on the reverse
        // control stream. Incarnations protect the independent bulk lane; this map protects the
        // intentionally untagged generation-7 control stream from premature range reuse.
        let pending_disconnects: Arc<Mutex<HashMap<ClientIncarnation, PendingClientDisconnect>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn the ring writer task (client frames → rx_ring → guest).
        let shared_for_writer = Arc::clone(&self.shared);
        let mut ring_writer_handle = tokio::spawn(ring_writer_task(shared_for_writer, agent_rx));
        let clock_sync_handle = spawn_clock_sync_task(agent_tx.clone());
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
            let handle = tokio::spawn(async move {
                let _ = failure_tx
                    .send(bulk_ring_writer_task(shared, rx).await)
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
                clients: clients_for_reader,
                log_writer: log_writer_for_reader,
                session_registry: registry_for_reader,
                pending_disconnects: Arc::clone(&pending_disconnects),
                bulk_writer: bulk_tx.clone(),
            },
        ));

        // Accept loop.
        let mut relay_failure = None;
        let mut control_writer_usable = false;
        let mut can_observe_failure_terminals = false;
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok(stream) => {
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

                            // Establish the dual-port range owner on the ordered control lane before
                            // the SDK sees its handshake and can submit work on either physical lane.
                            if let Some(incarnation) = incarnation
                                && let Err(error) = send_relay_client_connected(
                                    &agent_tx,
                                    id_start,
                                    id_end_exclusive,
                                    incarnation,
                                )
                                .await
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
                            let writer_disconnect_tx = disconnect_tx.clone();
                            tokio::spawn(client_writer_task(
                                slot,
                                writer_half,
                                write_rx,
                                writer_disconnect_tx,
                            ));

                            let active_bulk = Arc::new(std::sync::Mutex::new(HashMap::new()));

                            // Register the client.
                            {
                                let mut map = clients.lock().await;
                                map.insert(slot, ClientState {
                                    incarnation,
                                    active_sessions: HashSet::new(),
                                    active_bulk: Arc::clone(&active_bulk),
                                    write_tx,
                                    write_budget: Arc::new(Semaphore::new(
                                        CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY,
                                    )),
                                    disconnect_tx,
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
                                disconnect_rx,
                            ));
                        }
                        Err(e) => {
                            tracing::error!("agent relay: accept error: {e}");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("agent relay: shutdown signal received");
                        break;
                    }
                }
                reader_result = &mut ring_reader_handle => {
                    control_writer_usable = true;
                    relay_failure = Some(match reader_result {
                        Ok(Ok(())) => RuntimeError::Custom(
                            "agent relay: console reader stopped unexpectedly".into(),
                        ),
                        Ok(Err(error)) => error,
                        Err(error) => RuntimeError::Custom(format!(
                            "agent relay: console reader task failed: {error}"
                        )),
                    });
                    break;
                }
                writer_result = &mut ring_writer_handle => {
                    relay_failure = Some(match writer_result {
                        Ok(Ok(())) => RuntimeError::Custom(
                            "agent relay: control console writer stopped unexpectedly".into(),
                        ),
                        Ok(Err(error)) => error,
                        Err(error) => RuntimeError::Custom(format!(
                            "agent relay: control console writer task failed: {error}"
                        )),
                    });
                    break;
                }
                Some(result) = bulk_failure_rx.recv() => {
                    control_writer_usable = true;
                    can_observe_failure_terminals = true;
                    relay_failure = Some(match result {
                        Ok(()) => RuntimeError::Custom(
                            "agent relay: bulk console writer stopped unexpectedly".into(),
                        ),
                        Err(error) => error,
                    });
                    break;
                }
            }
        }

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
        self.listener.cleanup(&self.endpoint);

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
        self.listener.cleanup(&self.endpoint);
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
        Self {
            data,
            completion: None,
        }
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

pub(crate) fn push_guest_frame_until(
    shared: &ConsoleSharedState,
    frame: Vec<u8>,
    timeout: std::time::Duration,
) -> RuntimeResult<()> {
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

/// Drain one client's byte-bounded mailbox through a single batching writer.
async fn client_writer_task<W>(
    slot: u32,
    mut writer: W,
    mut write_rx: mpsc::UnboundedReceiver<ClientWrite>,
    disconnect_tx: watch::Sender<bool>,
) where
    W: AsyncWrite + Unpin,
{
    let mut batch = VecDeque::new();
    let mut deferred = None;
    loop {
        let write = match deferred.take() {
            Some(write) => write,
            None => match write_rx.recv().await {
                Some(write) => write,
                None => break,
            },
        };
        let mut batch_bytes = write.data.len();
        batch.push_back(write);
        while batch.len() < CLIENT_WRITE_BATCH_FRAMES && batch_bytes < CLIENT_WRITE_BATCH_BYTES {
            let Ok(write) = write_rx.try_recv() else {
                break;
            };
            if batch_bytes.saturating_add(write.data.len()) > CLIENT_WRITE_BATCH_BYTES {
                deferred = Some(write);
                break;
            }
            batch_bytes = batch_bytes.saturating_add(write.data.len());
            batch.push_back(write);
        }

        if let Err(error) = write_client_batch(&mut writer, &mut batch).await {
            tracing::error!("agent relay: client writer slot={slot} failed: {error}");
            let _ = disconnect_tx.send(true);
            break;
        }
    }
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
            .map(|write| IoSlice::new(&write.data))
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
            if remaining < front.data.len() {
                front.data.advance(remaining);
                remaining = 0;
            } else {
                remaining -= front.data.len();
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

/// Background task that pushes client frames into the rx_ring for the guest.
/// Retries on full ring with backoff to avoid dropping frames.
async fn ring_writer_task(
    shared: Arc<ConsoleSharedState>,
    mut rx: mpsc::Receiver<ControlWrite>,
) -> RuntimeResult<()> {
    #[cfg(unix)]
    let capacity_fd = match AsyncFd::new(shared.rx_capacity_wake.as_raw_fd()) {
        Ok(fd) => fd,
        Err(error) => {
            return Err(RuntimeError::Custom(format!(
                "agent relay: failed to watch console capacity: {error}"
            )));
        }
    };

    while let Some(write) = rx.recv().await {
        let ControlWrite {
            mut data,
            completion,
        } = write;
        let mut attempts = 0u64;
        loop {
            match shared.rx_ring.push(data) {
                Ok(()) => {
                    shared.rx_wake.wake();
                    if let Some(completion) = completion {
                        let _ = completion.send(());
                    }
                    break;
                }
                Err(returned) => {
                    attempts = attempts.saturating_add(1);
                    if attempts == 50 || attempts.is_multiple_of(500) {
                        tracing::warn!(
                            attempts,
                            "agent relay: rx_ring full, waiting to deliver frame"
                        );
                    }
                    data = returned;
                    if shared.is_closed() {
                        return Ok(());
                    }

                    shared.rx_capacity_wake.drain();
                    if shared.rx_ring.can_fit(data.len()) {
                        continue;
                    }

                    #[cfg(unix)]
                    {
                        let mut guard = match capacity_fd.readable().await {
                            Ok(guard) => guard,
                            Err(error) => {
                                return Err(RuntimeError::Custom(format!(
                                    "agent relay: console capacity wait failed: {error}"
                                )));
                            }
                        };
                        guard.clear_ready();
                    }

                    #[cfg(windows)]
                    {
                        let shared_for_wait = Arc::clone(&shared);
                        let _ = tokio::task::spawn_blocking(move || {
                            shared_for_wait
                                .rx_capacity_wake
                                .wait_timeout(std::time::Duration::from_secs(60))
                        })
                        .await;
                    }
                }
            }
        }
    }
    tracing::debug!("agent relay: ring writer task exiting");
    Ok(())
}

/// Apply deficit round robin before admitting client raw records to the bulk console ring.
async fn bulk_ring_writer_task(
    shared: Arc<ConsoleSharedState>,
    mut rx: mpsc::Receiver<BulkWriterCommand>,
) -> RuntimeResult<()> {
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

    while let Some(command) = rx.recv().await {
        apply_bulk_writer_command(command, &mut flows, &mut active, &mut retired)?;
        while let Ok(command) = rx.try_recv() {
            apply_bulk_writer_command(command, &mut flows, &mut active, &mut retired)?;
        }

        while !active.is_empty() {
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
                }

                if flows.get(&key).is_some_and(|flow| flow.queue.is_empty()) {
                    flows.remove(&key);
                } else {
                    active.push_back(key);
                }
            }
            while let Ok(command) = rx.try_recv() {
                apply_bulk_writer_command(command, &mut flows, &mut active, &mut retired)?;
            }
            tokio::task::yield_now().await;
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

/// Validate the fixed outer and generation-7 bulk headers without copying the payload.
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
    // Keep the incarnation outside the unchanged generation-7 frame. Two queue fragments avoid
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
    push_bulk_fragment(
        shared,
        write.data,
        #[cfg(unix)]
        capacity_fd,
    )
    .await
}

async fn push_bulk_fragment(
    shared: &Arc<ConsoleSharedState>,
    mut data: Bytes,
    #[cfg(unix)] capacity_fd: &AsyncFd<i32>,
) -> bool {
    loop {
        match shared.rx_ring.push(data) {
            Ok(()) => {
                shared.rx_wake.wake();
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

                #[cfg(unix)]
                {
                    let Ok(mut guard) = capacity_fd.readable().await else {
                        return false;
                    };
                    guard.clear_ready();
                }
                #[cfg(windows)]
                {
                    let shared = Arc::clone(shared);
                    let _ = tokio::task::spawn_blocking(move || {
                        shared
                            .rx_capacity_wake
                            .wait_timeout(std::time::Duration::from_secs(60))
                    })
                    .await;
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
            shared,
            GuestLane::Control,
            dual_port,
            range_lease_active,
            control_lane_tx,
            control_lane_budget,
        )
        .await;
        let _ = control_failure_tx.send((GuestLane::Control, result)).await;
    });
    let bulk_handle = bulk_shared.map(|shared| {
        tokio::spawn(async move {
            let result = lane_reader_task(
                shared,
                GuestLane::Bulk,
                true,
                range_lease_active,
                bulk_lane_tx,
                bulk_lane_budget,
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

            if let Err(error) = route.write_tx.send(ClientWrite {
                data: frame.data,
                _lane_permit: lane_permit,
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

/// Read and route the single ordered guest stream without dual-port actor hops.
async fn combined_ring_reader_task(
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
    let mut buf = BytesMut::new();

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
async fn lane_reader_task(
    shared: Arc<ConsoleSharedState>,
    lane: GuestLane,
    dual_port: bool,
    range_lease_active: bool,
    event_tx: mpsc::Sender<LaneEvent>,
    budget: Arc<Semaphore>,
) -> RuntimeResult<()> {
    #[cfg(unix)]
    let async_fd = AsyncFd::new(shared.tx_wake.as_raw_fd()).map_err(RuntimeError::Io)?;
    let mut buf = BytesMut::new();

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
    agent_tx: mpsc::Sender<ControlWrite>,
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
    mut disconnect_rx: watch::Receiver<bool>,
) {
    loop {
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

        let decoded_message = (frame.flags != FLAG_BULK)
            .then(|| decode_frame(frame.data.as_ref()).ok())
            .flatten();
        let message_type = decoded_message.as_ref().map(|message| message.t);
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
                tracing::error!(
                    id = frame.id,
                    "agent relay: failed to register client operation"
                );
                break;
            }
        }

        if let Some(kind) = opened_bulk_kind {
            let duplicate = active_bulk.lock().unwrap().insert(frame.id, kind).is_some();
            if duplicate {
                tracing::error!(
                    id = frame.id,
                    "agent relay: client reused an active bulk correlation"
                );
                break;
            }
        }

        let bulk_metadata = if frame.flags == FLAG_BULK {
            let Ok(metadata) = bulk_wire_metadata(&frame.data) else {
                tracing::error!(id = frame.id, "agent relay: malformed client bulk record");
                break;
            };
            Some(metadata)
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
            if bulk_tx
                .send(BulkWriterCommand::Write(BulkWrite {
                    id: frame.id,
                    incarnation,
                    data: frame.data,
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
        } else if agent_tx.send(frame.data.into()).await.is_err() {
            tracing::error!("agent relay: control ring writer channel closed");
            break;
        }
    }

    // Client disconnected — send SIGKILL for each active session.
    let active_sessions = {
        let mut map = clients.lock().await;
        if let Some(client) = map.remove(&slot) {
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

            if agent_tx.send(Bytes::from(buf).into()).await.is_err() {
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
    agent_tx: &mpsc::Sender<ControlWrite>,
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
        .send(Bytes::copy_from_slice(&frame).into())
        .await
        .map_err(|_| RuntimeError::Custom("agent control writer stopped".into()))
}

/// Send cleanup and, in dual-port mode, register the reverse-lane drain acknowledgement first.
async fn begin_relay_client_disconnect(
    agent_tx: &mpsc::Sender<ControlWrite>,
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
    agent_tx: &mpsc::Sender<ControlWrite>,
    id_start: u32,
    id_end_exclusive: u32,
    incarnation: Option<ClientIncarnation>,
) -> RuntimeResult<()> {
    send_relay_lifecycle(
        agent_tx,
        MessageType::RelayClientDisconnected,
        &RelayClientDisconnected {
            id_start,
            id_end_exclusive,
            incarnation,
        },
    )
    .await
}

async fn send_relay_lifecycle<T: serde::Serialize>(
    agent_tx: &mpsc::Sender<ControlWrite>,
    message_type: MessageType,
    payload: &T,
) -> RuntimeResult<()> {
    let message = Message::with_payload(message_type, 0, payload)
        .map_err(|error| RuntimeError::Custom(format!("encode relay lifecycle: {error}")))?;
    let mut frame = Vec::new();
    codec::encode_to_buf(&message, &mut frame)
        .map_err(|error| RuntimeError::Custom(format!("encode relay lifecycle frame: {error}")))?;
    agent_tx
        .send(Bytes::from(frame).into())
        .await
        .map_err(|_| RuntimeError::Custom("agent control writer stopped".into()))
}

/// Publish typed cancellation for every active raw-bulk operation while control is still usable.
async fn handle_relay_transport_failure(
    agent_tx: &mpsc::Sender<ControlWrite>,
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
                data: Bytes::from(frame),
                completion: Some(completion),
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

/// Validate the complete generation-7 flag byte without interpreting an opaque frame body.
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

    fn encoded_message<T: serde::Serialize>(t: MessageType, payload: &T) -> Vec<u8> {
        encoded_message_id(t, 0, payload)
    }

    fn encoded_message_id<T: serde::Serialize>(t: MessageType, id: u32, payload: &T) -> Vec<u8> {
        let msg = Message::with_payload(t, id, payload).unwrap();
        let mut frame = Vec::new();
        codec::encode_to_buf(&msg, &mut frame).unwrap();
        frame
    }

    fn encoded_raw_flow(id: u32, flow: BulkFlow, offset: u64, payload: &'static [u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        codec::encode_bulk_to_buf(
            &BulkRecord {
                id,
                kind: BulkKind::Filesystem,
                flow,
                offset,
                payload: Bytes::from_static(payload),
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
            data: Bytes::from_static(b"control frame"),
            completion: Some(completion),
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
    async fn combined_leased_disconnect_releases_slot_without_a_merger() {
        let slot = 0;
        let incarnation = [0x82; CLIENT_INCARNATION_SIZE];
        let (id_start, id_end_exclusive) = relay_client_id_range(slot).unwrap();
        let (reader, peer) = tokio::io::duplex(64);
        drop(peer);
        let (agent_tx, mut agent_rx) = mpsc::channel(4);
        let (write_tx, _write_rx) = mpsc::unbounded_channel();
        let (disconnect_tx, disconnect_rx) = watch::channel(false);
        let active_bulk = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let clients = Arc::new(Mutex::new(HashMap::from([(
            slot,
            ClientState {
                incarnation: Some(incarnation),
                active_sessions: HashSet::new(),
                active_bulk: Arc::clone(&active_bulk),
                write_tx,
                write_budget: Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY)),
                disconnect_tx,
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
            disconnect_rx,
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
                data,
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
                data: late_data,
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
                Arc::clone(&shared),
                GuestLane::Bulk,
                true,
                true,
                frame_tx,
                budget,
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
                data,
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
            data,
            flow: BulkFlow::HostToGuest,
            payload_len: PAYLOAD.len(),
            _permit: permit,
        }))
        .await
        .unwrap();
        drop(tx);

        let task = tokio::spawn(bulk_ring_writer_task(Arc::clone(&shared), rx));
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
            data,
            flow: record.flow,
            payload_len: record.payload.len(),
            _permit: permit,
        }))
        .await
        .unwrap();
        drop(tx);

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bulk_ring_writer_task(Arc::clone(&shared), rx),
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
                data: Bytes::from_static(b"abc"),
                _lane_permit: first_lane,
                _client_permit: first_client,
            },
            ClientWrite {
                data: Bytes::from_static(b"defgh"),
                _lane_permit: second_lane,
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
                data: Bytes::from(vec![0u8; FRAME_BYTES]),
                _lane_permit: lane_permit,
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
            },
        )])));
        let frame = encoded_message_id(MessageType::Pong, 1, &microsandbox_protocol::core::Pong {});
        let reader = tokio::spawn(combined_ring_reader_task(
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

        assert_eq!(output.data.as_ref(), frame);
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
                ..Default::default()
            },
        );
        shared.tx_ring.push(ready.clone()).unwrap();
        shared.tx_wake.wake();

        relay.wait_ready().unwrap();

        assert_eq!(relay.ready_frame.as_deref(), Some(ready.as_slice()));
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
}
