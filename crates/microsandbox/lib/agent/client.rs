//! SDK-side client for connecting to the sandbox agent relay.
//!
//! [`AgentClient`] communicates over a Unix domain socket to the sandbox's
//! relay. During connection, the relay assigns a non-overlapping correlation ID
//! range and sends the cached `core.ready` payload so the client can begin
//! issuing commands immediately.
//!
//! Two API tiers share one socket and one reader task:
//!
//! - **Raw** ([`request_raw`](AgentClient::request_raw),
//!   [`stream_raw`](AgentClient::stream_raw),
//!   [`send_raw`](AgentClient::send_raw)) — exchange [`RawFrame`]s. The SDK
//!   handles framing and correlation IDs; CBOR encoding/decoding is left to
//!   the caller. Use this when wrapping the client for other languages.
//! - **Typed** ([`request`](AgentClient::request),
//!   [`stream`](AgentClient::stream), [`send`](AgentClient::send)) — same
//!   primitives over [`Message`]; the SDK serializes payloads with CBOR.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use std::time::Duration;

use microsandbox_protocol::{
    codec::{self, MAX_FRAME_SIZE, RawFrame},
    core::Ready,
    message::{FLAG_TERMINAL, FRAME_HEADER_SIZE, Message, MessageType, PROTOCOL_VERSION},
};
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::error::{AgentClientError, AgentClientResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default handshake timeout used by [`AgentClient::connect`].
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
// compatibility for versions before 0.5 is no longer supported.
const LEGACY_PROTOCOL_VERSION: u8 = 1;
const LEGACY_RELAY_ID_RANGE_STEP: u32 = u32::MAX / 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Agent protocol generation spoken by a connected sandbox relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProtocol {
    /// Current protocol generation.
    Current,

    /// pre-0.5 microsandbox relay handshake and agent protocol.
    ///
    /// TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
    /// compatibility for versions before 0.5 is no longer supported.
    LegacyV1,
}

/// Client for communicating with agentd through the agent relay.
///
/// See the module-level docs for an overview of the two API tiers.
pub struct AgentClient {
    /// Writer half of the Unix socket connection.
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    /// Next correlation ID to allocate (starts at `id_min`).
    next_id: AtomicU32,
    /// Lower bound (inclusive) of the assigned ID range, used for wrap-around.
    id_min: u32,
    /// Upper bound (exclusive) of the assigned ID range.
    id_max: u32,
    /// Agent protocol generation for this connection.
    protocol: AgentProtocol,
    /// Negotiated protocol generation: `min(our PROTOCOL_VERSION, the
    /// generation the sandbox echoed in its `core.ready` frame)`. Drives the
    /// capability gate on the typed send path. Distinct from [`Self::protocol`],
    /// which selects the wire codec; see `VERSIONING.md`.
    negotiated_version: u8,
    /// Pending response channels keyed by correlation ID.
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<RawFrame>>>>,
    /// Background reader task handle.
    reader_handle: JoinHandle<()>,
    /// Cached `core.ready` frame body (raw CBOR bytes) from the relay handshake.
    ready_body: Vec<u8>,
    /// Decoded `core.ready` payload from the relay handshake.
    ready: Ready,
}

//--------------------------------------------------------------------------------------------------
// Methods: Connection lifecycle
//--------------------------------------------------------------------------------------------------

impl AgentProtocol {
    fn version(self) -> u8 {
        match self {
            Self::Current => PROTOCOL_VERSION,
            Self::LegacyV1 => LEGACY_PROTOCOL_VERSION,
        }
    }
}

impl AgentClient {
    /// Connect to the sandbox's agent relay socket using the default 10s
    /// handshake timeout.
    pub async fn connect(sock_path: impl AsRef<Path>) -> AgentClientResult<Self> {
        Self::connect_with_timeout(sock_path, DEFAULT_HANDSHAKE_TIMEOUT).await
    }

    /// Connect to the sandbox's agent relay socket using an explicit
    /// handshake timeout.
    pub async fn connect_with_timeout(
        sock_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        let deadline = Instant::now() + timeout;
        Self::connect_with_deadline(sock_path, deadline).await
    }

    /// Connect with an explicit handshake deadline.
    ///
    /// `deadline` bounds both handshake reads. Without it, an accepted
    /// connection that stalls (e.g. a sandbox alive but wedged before
    /// writing the handshake bytes) would block this call indefinitely.
    pub async fn connect_with_deadline(
        sock_path: impl AsRef<Path>,
        deadline: Instant,
    ) -> AgentClientResult<Self> {
        let sock_path = sock_path.as_ref();
        let stream =
            UnixStream::connect(sock_path)
                .await
                .map_err(|source| AgentClientError::Connect {
                    path: sock_path.to_path_buf(),
                    source,
                })?;

        let (mut reader, writer) = stream.into_split();

        // Current handshake:
        // [id_min: u32 BE][id_max: u32 BE][ready_frame_bytes...]
        //
        // Legacy pre-0.5 handshake:
        // [id_offset: u32 BE][ready_frame_bytes...]
        //
        // Reading 8 bytes up-front lets us distinguish the two forms. For
        // legacy relays, the second word is the ready-frame length prefix.
        let mut range_buf = [0u8; 8];
        tokio::time::timeout_at(deadline, reader.read_exact(&mut range_buf))
            .await
            .map_err(|_| {
                AgentClientError::Handshake(
                    "read id range: timed out before relay sent bytes".into(),
                )
            })?
            .map_err(|e| AgentClientError::Handshake(format!("read id range: {e}")))?;
        let id_start_or_offset = u32::from_be_bytes(range_buf[0..4].try_into().unwrap());
        let id_max_or_frame_len = u32::from_be_bytes(range_buf[4..8].try_into().unwrap());

        let legacy_handshake =
            looks_like_legacy_relay_handshake(id_start_or_offset, id_max_or_frame_len);
        let (id_min, id_max, ready_frame, protocol) = if legacy_handshake {
            // TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
            // compatibility for versions before 0.5 is no longer supported.
            let id_offset = id_start_or_offset;
            let ready_frame = read_raw_frame_after_len_prefix(
                &mut reader,
                range_buf[4..8].try_into().unwrap(),
                deadline,
            )
            .await?;
            (
                id_offset.saturating_add(1),
                id_offset.saturating_add(LEGACY_RELAY_ID_RANGE_STEP),
                ready_frame,
                AgentProtocol::LegacyV1,
            )
        } else if id_start_or_offset >= id_max_or_frame_len {
            return Err(AgentClientError::Handshake(format!(
                "invalid relay id range: start={id_start_or_offset}, end={id_max_or_frame_len}"
            )));
        } else {
            let ready_frame = tokio::time::timeout_at(deadline, codec::read_raw_frame(&mut reader))
                .await
                .map_err(|_| {
                    AgentClientError::Handshake(
                        "read ready frame: timed out before relay sent frame".into(),
                    )
                })?
                .map_err(|e| AgentClientError::Handshake(format!("read ready frame: {e}")))?;
            (
                id_start_or_offset,
                id_max_or_frame_len,
                ready_frame,
                AgentProtocol::Current,
            )
        };
        let ready_msg = codec::raw_frame_to_message(ready_frame.clone())
            .map_err(|e| AgentClientError::Handshake(format!("decode ready frame: {e}")))?;
        if ready_msg.t != MessageType::Ready {
            return Err(AgentClientError::Handshake(format!(
                "expected core.ready frame, got {}",
                ready_msg.t.as_str()
            )));
        }
        let ready: Ready = ready_msg
            .payload()
            .map_err(|e| AgentClientError::Handshake(format!("decode ready payload: {e}")))?;

        // The negotiated capability generation is the lower of what we speak and
        // what the sandbox echoed in its ready frame (`ready_msg.v`). For the
        // load-bearing case — a newer host meeting an older runtime — this is the
        // runtime's generation, so the send gate withholds features it can't
        // handle. The codec generation (`protocol`) is negotiated separately.
        let negotiated_version = protocol.version().min(ready_msg.v);

        tracing::info!(
            id_min,
            id_max,
            protocol = ?protocol,
            ready_bytes = ready_frame.body.len(),
            boot_time_ns = ready.boot_time_ns,
            "agent client: connected to relay"
        );
        if protocol == AgentProtocol::LegacyV1 {
            // TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
            // compatibility for versions before 0.5 is no longer supported.
            tracing::warn!(
                "agent client: connected to a sandbox started before microsandbox 0.5; exec compatibility is temporary and filesystem/SFTP require stop/start"
            );
        }

        let pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<RawFrame>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let reader_handle = tokio::spawn(reader_loop(reader, Arc::clone(&pending)));
        let writer = Arc::new(Mutex::new(writer));

        Ok(Self {
            writer,
            next_id: AtomicU32::new(first_request_id(id_min)),
            id_min,
            id_max,
            protocol,
            negotiated_version,
            pending,
            reader_handle,
            ready_body: ready_frame.body,
            ready,
        })
    }

    /// Resolve a sandbox name to its agent socket path and connect.
    ///
    /// The socket lives under the SDK's configured runtime directory at a
    /// short, name-derived path. Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn connect_sandbox(name: &str) -> AgentClientResult<Self> {
        Self::connect_sandbox_with_timeout(name, DEFAULT_HANDSHAKE_TIMEOUT).await
    }

    /// Resolve a sandbox name to its agent socket path and connect with an
    /// explicit handshake timeout.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn connect_sandbox_with_timeout(
        name: &str,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        if let Some(message) = crate::sandbox::sandbox_name_validation_message(name) {
            return Err(AgentClientError::InvalidSandboxName(message));
        }

        let mut last_error = None;
        for sock_path in crate::runtime::sandbox_agent_socket_path_candidates(name) {
            if !sock_path.exists() {
                continue;
            }

            match Self::connect_with_timeout(&sock_path, timeout).await {
                Ok(client) => return Ok(client),
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) => Err(error),
            None => Err(AgentClientError::SandboxNotFound(name.to_string())),
        }
    }

    /// Close the connection. Drops the writer and aborts the reader task;
    /// any in-flight requests resolve with [`AgentClientError::Closed`].
    pub async fn close(self) {
        // Drop runs: reader aborts via Drop impl, writer closes when the
        // last Arc reference dies. Senders in `pending` drop with self,
        // resolving outstanding waiters.
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Raw transport (CBOR-blind)
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// One-shot raw request: alloc id, send a frame with `(flags, body)`,
    /// await one response frame with the matching id.
    ///
    /// Use this for protocol RPCs that produce exactly one terminal response
    /// (e.g. `FsRequest` → `FsResponse`).
    pub async fn request_raw(&self, flags: u8, body: Vec<u8>) -> AgentClientResult<RawFrame> {
        let id = self.alloc_id();
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(id, tx);

        if let Err(e) = self.write_frame(id, flags, &body).await {
            self.pending.lock().await.remove(&id);
            return Err(e);
        }

        rx.recv().await.ok_or(AgentClientError::ReaderClosed(id))
    }

    /// Open a streaming raw session: alloc id, register a subscription,
    /// send the opening frame, return `(id, receiver)`.
    ///
    /// The receiver yields every frame the relay forwards for this `id`
    /// until a frame with [`FLAG_TERMINAL`] arrives or the receiver is dropped.
    /// Use [`send_raw`](Self::send_raw) with the returned id to send
    /// follow-up frames within the session.
    pub async fn stream_raw(
        &self,
        flags: u8,
        body: Vec<u8>,
    ) -> AgentClientResult<(u32, mpsc::UnboundedReceiver<RawFrame>)> {
        let id = self.alloc_id();
        let (tx, rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(id, tx);

        if let Err(e) = self.write_frame(id, flags, &body).await {
            self.pending.lock().await.remove(&id);
            return Err(e);
        }

        Ok((id, rx))
    }

    /// Send a follow-up raw frame on an existing correlation id.
    ///
    /// Use for messages that belong to a session started via
    /// [`stream_raw`](Self::stream_raw) (e.g. `ExecStdin`, `ExecSignal`,
    /// `ExecResize`, `FsData` chunks).
    pub async fn send_raw(&self, id: u32, flags: u8, body: &[u8]) -> AgentClientResult<()> {
        self.write_frame(id, flags, body).await
    }

    /// The cached `core.ready` handshake frame body bytes (CBOR-encoded).
    ///
    /// Useful for bindings that want to deserialize the ready payload with
    /// their own CBOR tooling. For typed access, use [`ready`](Self::ready).
    pub fn ready_bytes(&self) -> &[u8] {
        &self.ready_body
    }

    /// Agent protocol generation for this connection.
    pub fn protocol(&self) -> AgentProtocol {
        self.protocol
    }

    /// Returns `true` if this connection is using the legacy pre-0.5 protocol.
    pub fn is_legacy_protocol(&self) -> bool {
        self.protocol == AgentProtocol::LegacyV1
    }

    /// The negotiated protocol generation for this connection: the lower of what
    /// this client speaks and what the sandbox advertised at handshake.
    pub fn negotiated_version(&self) -> u8 {
        self.negotiated_version
    }

    /// The runtime's self-reported package version, taken from its `core.ready`
    /// frame. Empty when the runtime predates this field (an older agent), in
    /// which case fall back to the generation for diagnostics.
    pub fn agent_version(&self) -> &str {
        &self.ready.agent_version
    }

    /// Whether the connected sandbox is new enough to handle the given message
    /// type. The single source of truth for feature gating: callers that can't
    /// gate by sending (e.g. the SSH/SFTP layer) consult this instead of
    /// inspecting the protocol generation directly.
    pub fn supports(&self, t: MessageType) -> bool {
        t.min_protocol_version() <= self.negotiated_version
    }

    /// Reject a message type the connected sandbox is too old to handle, against
    /// this connection's negotiated generation. Fails before any bytes are sent,
    /// so only that one operation fails and the session continues.
    pub fn ensure_version_compat(&self, t: MessageType) -> AgentClientResult<()> {
        Self::ensure_version_compat_for(t, self.negotiated_version)
    }

    /// Check a message type against an explicit negotiated generation.
    ///
    /// The single place the rule lives. Exposed for callers that hold the
    /// negotiated generation but not the live client (e.g. the SSH/SFTP layer).
    pub fn ensure_version_compat_for(t: MessageType, negotiated: u8) -> AgentClientResult<()> {
        if t.is_available_at(negotiated) {
            return Ok(());
        }
        Err(AgentClientError::UnsupportedOperation {
            msg_type: t.as_str(),
            needs: t.min_protocol_version(),
            peer: negotiated,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Typed transport (CBOR-aware)
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// One-shot typed request. Flags are derived from the message type.
    pub async fn request<T: Serialize>(
        &self,
        t: MessageType,
        payload: &T,
    ) -> AgentClientResult<Message> {
        self.ensure_version_compat(t)?;
        let flags = t.flags();
        let body = encode_message_body(self.protocol.version(), t, payload)?;
        let frame = self.request_raw(flags, body).await?;
        Ok(codec::raw_frame_to_message(frame)?)
    }

    /// Open a streaming typed session. Flags are derived from the message type.
    /// Returns the assigned id and a typed receiver.
    pub async fn stream<T: Serialize>(
        &self,
        t: MessageType,
        payload: &T,
    ) -> AgentClientResult<(u32, mpsc::UnboundedReceiver<Message>)> {
        self.ensure_version_compat(t)?;
        let flags = t.flags();
        let body = encode_message_body(self.protocol.version(), t, payload)?;
        let (id, raw_rx) = self.stream_raw(flags, body).await?;

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(decode_stream_task(raw_rx, tx));
        Ok((id, rx))
    }

    /// Send a follow-up typed message on an existing correlation id.
    pub async fn send<T: Serialize>(
        &self,
        id: u32,
        t: MessageType,
        payload: &T,
    ) -> AgentClientResult<()> {
        self.ensure_version_compat(t)?;
        let flags = t.flags();
        let body = encode_message_body(self.protocol.version(), t, payload)?;
        self.write_frame(id, flags, &body).await
    }

    /// Decode the cached handshake `core.ready` payload.
    pub fn ready(&self) -> AgentClientResult<Ready> {
        Ok(self.ready.clone())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Internals
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// Allocate a unique correlation ID from the relay-assigned range.
    ///
    /// Wraps around within the assigned range if the counter overflows.
    fn alloc_id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && id >= self.id_min && id < self.id_max {
                return id;
            }
            self.next_id
                .store(first_request_id(self.id_min), Ordering::Relaxed);
        }
    }

    /// Write a single framed message to the socket.
    async fn write_frame(&self, id: u32, flags: u8, body: &[u8]) -> AgentClientResult<()> {
        let mut buf = Vec::with_capacity(4 + 5 + body.len());
        codec::encode_raw_to_buf(
            &RawFrame {
                id,
                flags,
                body: body.to_vec(),
            },
            &mut buf,
        )?;

        let mut writer = self.writer.lock().await;
        tokio::io::AsyncWriteExt::write_all(&mut *writer, &buf).await?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn looks_like_legacy_relay_handshake(_id_min: u32, id_max: u32) -> bool {
    // TODO(upgrade-0.6): Remove in 0.6.x or later once pre-0.5 relay
    // handshakes are no longer accepted.
    // In the legacy relay handshake, the first 4 bytes are the id offset and
    // the next 4 bytes are already the ready-frame length prefix. In the v2
    // handshake, the second word is the exclusive upper id bound, which is far
    // larger than any valid frame length.
    id_max >= FRAME_HEADER_SIZE as u32 && id_max <= MAX_FRAME_SIZE
}

fn first_request_id(id_min: u32) -> u32 {
    id_min.max(1)
}

async fn read_raw_frame_after_len_prefix<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    len_buf: [u8; 4],
    deadline: Instant,
) -> AgentClientResult<RawFrame> {
    let frame_len = u32::from_be_bytes(len_buf);
    if frame_len > MAX_FRAME_SIZE {
        return Err(AgentClientError::Handshake(format!(
            "legacy ready frame too large: {frame_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }
    if frame_len < FRAME_HEADER_SIZE as u32 {
        return Err(AgentClientError::Handshake(format!(
            "legacy ready frame too short: {frame_len} bytes"
        )));
    }

    let mut data = vec![0u8; frame_len as usize];
    tokio::time::timeout_at(deadline, reader.read_exact(&mut data))
        .await
        .map_err(|_| {
            AgentClientError::Handshake(
                "read legacy ready frame: timed out before relay sent frame".into(),
            )
        })?
        .map_err(|e| AgentClientError::Handshake(format!("read legacy ready frame: {e}")))?;

    let id = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let flags = data[4];
    let body = data[FRAME_HEADER_SIZE..].to_vec();

    Ok(RawFrame { id, flags, body })
}

/// Background task that reads frames from the relay and dispatches them to
/// pending channels by correlation ID. Operates on raw frames — no CBOR.
async fn reader_loop(
    mut reader: tokio::net::unix::OwnedReadHalf,
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<RawFrame>>>>,
) {
    loop {
        let frame = match codec::read_raw_frame(&mut reader).await {
            Ok(frame) => frame,
            Err(e) => {
                tracing::debug!("agent client: reader EOF or error: {e}");
                break;
            }
        };

        let id = frame.id;
        let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;

        let mut map = pending.lock().await;
        if let Some(tx) = map.get(&id) {
            if tx.send(frame).is_err() {
                // Receiver dropped — clean up.
                map.remove(&id);
            } else if is_terminal {
                // Terminal frame delivered — remove subscription.
                map.remove(&id);
            }
        } else {
            tracing::trace!("agent client: no pending handler for id={id}");
        }
    }

    // Reader exited — drop all senders so outstanding receivers wake up.
    let mut map = pending.lock().await;
    map.clear();
}

/// Translate a stream of raw frames into typed messages.
async fn decode_stream_task(
    mut raw_rx: mpsc::UnboundedReceiver<RawFrame>,
    tx: mpsc::UnboundedSender<Message>,
) {
    while let Some(frame) = raw_rx.recv().await {
        match codec::raw_frame_to_message(frame) {
            Ok(msg) => {
                if tx.send(msg).is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("agent client: failed to decode frame in stream: {e}");
                // Continue — single malformed frame shouldn't kill the stream.
            }
        }
    }
}

/// Encode a typed payload to a CBOR `Message` body.
fn encode_message_body<T: Serialize>(
    version: u8,
    t: MessageType,
    payload: &T,
) -> AgentClientResult<Vec<u8>> {
    let mut msg = Message::with_payload(t, 0, payload)?;
    msg.v = version;
    let mut body = Vec::new();
    ciborium::into_writer(&msg, &mut body).map_err(microsandbox_protocol::ProtocolError::from)?;
    Ok(body)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_protocol::core::Ready;
    use microsandbox_protocol::exec::ExecRequest;
    use microsandbox_protocol::message::PROTOCOL_VERSION;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn connect_decodes_ready_payload() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "9.9.9".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::Current);
        // Both peers speak the current generation, so that is what is negotiated.
        assert_eq!(client.negotiated_version(), PROTOCOL_VERSION);
        assert!(client.supports(MessageType::FsRequest));
        // The runtime's self-reported version round-trips from the ready frame.
        assert_eq!(client.agent_version(), "9.9.9");
        let decoded = client.ready().unwrap();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);

        let raw_msg: Message = ciborium::from_reader(client.ready_bytes()).unwrap();
        assert_eq!(raw_msg.t, MessageType::Ready);
    }

    #[tokio::test]
    async fn connect_negotiates_down_to_older_guest_generation() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 1,
            init_time_ns: 2,
            ready_time_ns: 3,
            ..Default::default()
        };
        // A current-codec guest that advertises an older capability generation in
        // its ready frame (a runtime one generation behind this host).
        let mut ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        ready_msg.v = 1;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        // Current codec, but the capability gate is pinned to the guest's older
        // generation: min(host PROTOCOL_VERSION, guest's advertised 1) == 1.
        assert_eq!(client.protocol(), AgentProtocol::Current);
        assert_eq!(client.negotiated_version(), 1);
        // Exec is in the baseline; filesystem is not, at generation 1.
        assert!(client.supports(MessageType::ExecRequest));
        assert!(!client.supports(MessageType::FsRequest));
    }

    #[test]
    fn version_compat_across_generations() {
        use MessageType::{ExecRequest, FsRequest};
        // (message type, peer generation, expected allowed). Generation 1 is the
        // pre-0.5 legacy runtime (no filesystem); generation 2 introduced the
        // Fs* types; generation 3 is current.
        let cases = [
            (ExecRequest, 1, true),
            (ExecRequest, 2, true),
            (ExecRequest, 3, true),
            (FsRequest, 1, false),
            (FsRequest, 2, true),
            (FsRequest, 3, true),
        ];
        for (t, generation, allowed) in cases {
            assert_eq!(
                AgentClient::ensure_version_compat_for(t, generation).is_ok(),
                allowed,
                "{t:?} at generation {generation}"
            );
        }
    }

    #[test]
    fn version_compat_rejection_is_typed() {
        // Filesystem on the legacy (generation 1) runtime is rejected before any
        // send, with the structured error whose message tells the user to restart.
        let err =
            AgentClient::ensure_version_compat_for(MessageType::FsRequest, LEGACY_PROTOCOL_VERSION)
                .unwrap_err();
        assert!(matches!(
            err,
            AgentClientError::UnsupportedOperation {
                needs: 2,
                peer: 1,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn connect_accepts_legacy_relay_handshake() {
        assert_accepts_legacy_relay_handshake(0).await;
        assert_accepts_legacy_relay_handshake(268_435_455).await;
    }

    #[tokio::test]
    async fn legacy_relay_requests_use_v1_and_legacy_id_range() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        let id_offset = 268_435_455u32;
        let (frame_tx, frame_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&id_offset.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
            let frame = codec::read_raw_frame(&mut socket).await.unwrap();
            frame_tx.send(frame).unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();
        let request = ExecRequest {
            cmd: "/bin/true".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let (id, _rx) = client
            .stream(MessageType::ExecRequest, &request)
            .await
            .unwrap();

        let frame = frame_rx.await.unwrap();
        let message = codec::raw_frame_to_message(frame).unwrap();

        assert_eq!(id, id_offset + 1);
        assert_eq!(message.id, id_offset + 1);
        assert_eq!(message.v, LEGACY_PROTOCOL_VERSION);
        assert_eq!(message.t, MessageType::ExecRequest);
    }

    #[tokio::test]
    async fn connect_preserves_current_peer_protocol_version() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let mut ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        ready_msg.v = 2;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::Current);
        // The runtime reported generation 2, so that is the negotiated capability.
        assert_eq!(client.negotiated_version(), 2);
        // TCP forwarding (generation 4) is unavailable to a generation-2 runtime.
        assert!(!client.supports(MessageType::TcpConnect));
    }

    async fn assert_accepts_legacy_relay_handshake(id_offset: u32) {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = Ready {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&id_offset.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client =
            AgentClient::connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.protocol(), AgentProtocol::LegacyV1);
        let decoded = client.ready().unwrap();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AgentClient {
    fn drop(&mut self) {
        self.reader_handle.abort();
    }
}
