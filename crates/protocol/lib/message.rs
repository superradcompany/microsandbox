//! Message envelope and type definitions for the agent protocol.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::ProtocolResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 6;

/// Frame flag: this is the last message for the given correlation ID.
///
/// Set on terminal message types such as `ExecExited`, `FsResponse`, and `TcpClosed`.
pub const FLAG_TERMINAL: u8 = 0b0000_0001;

/// Frame flag: this is the first message of a new session.
///
/// Set on session-initiating message types such as `ExecRequest`, `FsRequest`, and `TcpConnect`.
pub const FLAG_SESSION_START: u8 = 0b0000_0010;

/// Frame flag: this message requests sandbox shutdown.
///
/// Set on `Shutdown` messages. The sandbox-process relay uses this to trigger
/// drain escalation (SIGTERM → SIGKILL) if the guest doesn't exit voluntarily.
pub const FLAG_SHUTDOWN: u8 = 0b0000_0100;

/// Size of the frame header fields that sit between the length prefix and the
/// CBOR payload: `[id: u32 BE][flags: u8]` = 5 bytes.
pub const FRAME_HEADER_SIZE: usize = 5;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The message envelope sent over the wire.
///
/// Each message contains a version, type, correlation ID, flags, and a CBOR payload.
///
/// Wire format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
///
/// The `id` and `flags` fields live in the binary frame header (outside CBOR)
/// so that relay intermediaries can route frames without CBOR parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Protocol generation, echoed into the frame.
    ///
    /// This is the single protocol version axis (see `VERSIONING.md`), the same
    /// number negotiated once at the handshake — not a second, message-local
    /// version. It is carried here so a frame is self-describing for debugging
    /// and telemetry; behavior is gated on the negotiated generation, not on
    /// reading this field per message.
    pub v: u8,

    /// Message type.
    pub t: MessageType,

    /// Correlation ID used to associate requests with responses and
    /// to identify exec sessions.
    ///
    /// Serialized in the binary frame header, not in CBOR.
    #[serde(skip)]
    pub id: u32,

    /// Frame flags computed from the message type.
    ///
    /// Serialized in the binary frame header, not in CBOR.
    #[serde(skip)]
    pub flags: u8,

    /// The CBOR-encoded payload bytes.
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
}

/// Identifies the type of a protocol message.
///
/// The `#[strum(serialize = ...)]` attribute on each variant is the single
/// source for its wire string: [`as_str`](Self::as_str) and
/// [`from_wire_str`](Self::from_wire_str) are derived from it, and
/// [`strum::IntoEnumIterator`] yields every variant for exhaustive iteration
/// (the schema snapshot) without a hand-maintained list.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
pub enum MessageType {
    /// Guest agent is ready.
    #[strum(serialize = "core.ready")]
    Ready,

    /// Guest reports init context before user mounts.
    #[strum(serialize = "core.init.resolved")]
    InitResolved,

    /// Host acknowledges init-context setup.
    #[strum(serialize = "core.init.ack")]
    InitAck,

    /// Host requests shutdown.
    #[strum(serialize = "core.shutdown")]
    Shutdown,

    /// Host relay reports that one SDK client disconnected.
    #[strum(serialize = "core.relay.client.disconnected")]
    RelayClientDisconnected,

    /// Host asks the guest to synchronize `CLOCK_REALTIME`.
    #[strum(serialize = "core.clock.sync")]
    ClockSync,

    /// Host checks whether the guest agent is reachable.
    #[strum(serialize = "core.ping")]
    Ping,

    /// Guest confirms that the guest agent is reachable.
    #[strum(serialize = "core.pong")]
    Pong,

    /// Host explicitly records sandbox activity.
    #[strum(serialize = "core.touch")]
    Touch,

    /// Guest confirms that sandbox activity was recorded.
    #[strum(serialize = "core.touched")]
    Touched,

    /// Peer reports a recoverable protocol-level error.
    #[strum(serialize = "core.error")]
    CoreError,

    /// Host requests command execution.
    #[strum(serialize = "core.exec.request")]
    ExecRequest,

    /// Guest confirms command started.
    #[strum(serialize = "core.exec.started")]
    ExecStarted,

    /// Host sends stdin data.
    #[strum(serialize = "core.exec.stdin")]
    ExecStdin,

    /// Guest reports that a prior `ExecStdin` write to the child's
    /// stdin failed (e.g. the child closed its read end). Non-terminal:
    /// the session continues and may still produce stdout/stderr and
    /// an exit code.
    #[strum(serialize = "core.exec.stdin.error")]
    ExecStdinError,

    /// Guest sends stdout data.
    #[strum(serialize = "core.exec.stdout")]
    ExecStdout,

    /// Guest sends stderr data.
    #[strum(serialize = "core.exec.stderr")]
    ExecStderr,

    /// Guest reports command exit.
    #[strum(serialize = "core.exec.exited")]
    ExecExited,

    /// Guest reports command failed to spawn (binary not found,
    /// permission denied, etc.). Distinct from `ExecExited` —
    /// `ExecFailed` means the user code never ran. Terminal.
    #[strum(serialize = "core.exec.failed")]
    ExecFailed,

    /// Host requests PTY resize.
    #[strum(serialize = "core.exec.resize")]
    ExecResize,

    /// Host sends signal to process.
    #[strum(serialize = "core.exec.signal")]
    ExecSignal,

    /// Host requests a filesystem operation.
    #[strum(serialize = "core.fs.request")]
    FsRequest,

    /// Guest sends a terminal filesystem response.
    #[strum(serialize = "core.fs.response")]
    FsResponse,

    /// Streaming file data chunk (bidirectional).
    #[strum(serialize = "core.fs.data")]
    FsData,

    /// Host requests a TCP connection from inside the guest.
    #[strum(serialize = "core.tcp.connect")]
    TcpConnect,

    /// Guest confirms that a TCP connection was opened.
    #[strum(serialize = "core.tcp.connected")]
    TcpConnected,

    /// TCP stream data chunk (bidirectional).
    #[strum(serialize = "core.tcp.data")]
    TcpData,

    /// One TCP stream side has closed its write half.
    #[strum(serialize = "core.tcp.eof")]
    TcpEof,

    /// Host requests a TCP session close.
    #[strum(serialize = "core.tcp.close")]
    TcpClose,

    /// Guest reports that a TCP session is closed. Terminal.
    #[strum(serialize = "core.tcp.closed")]
    TcpClosed,

    /// Guest reports that a TCP session failed. Terminal.
    #[strum(serialize = "core.tcp.failed")]
    TcpFailed,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Message {
    /// Creates a new message with the current protocol version and raw payload bytes.
    pub fn new(t: MessageType, id: u32, p: Vec<u8>) -> Self {
        let flags = t.flags();
        Self {
            v: PROTOCOL_VERSION,
            t,
            id,
            flags,
            p,
        }
    }

    /// Creates a new message by serializing the given payload to CBOR.
    pub fn with_payload<T: Serialize>(
        t: MessageType,
        id: u32,
        payload: &T,
    ) -> ProtocolResult<Self> {
        let mut p = Vec::new();
        ciborium::into_writer(payload, &mut p)?;
        let flags = t.flags();
        Ok(Self {
            v: PROTOCOL_VERSION,
            t,
            id,
            flags,
            p,
        })
    }

    /// Deserializes the payload bytes into the given type.
    pub fn payload<T: DeserializeOwned>(&self) -> ProtocolResult<T> {
        Ok(ciborium::from_reader(&self.p[..])?)
    }
}

impl MessageType {
    /// Computes the frame flags byte for this message type.
    pub fn flags(&self) -> u8 {
        match self {
            Self::Pong
            | Self::Touched
            | Self::CoreError
            | Self::ExecExited
            | Self::ExecFailed
            | Self::FsResponse
            | Self::TcpClosed
            | Self::TcpFailed => FLAG_TERMINAL,
            Self::ExecRequest | Self::FsRequest | Self::TcpConnect => FLAG_SESSION_START,
            Self::Shutdown => FLAG_SHUTDOWN,
            _ => 0,
        }
    }

    /// The protocol generation that introduced this message type.
    ///
    /// A per-type label on the single protocol generation axis (see
    /// `VERSIONING.md`), not a separate version counter. The send path gates on
    /// it: a type whose generation exceeds the peer's negotiated generation is
    /// rejected locally with a typed error instead of being sent to a peer that
    /// cannot handle it, so only that one feature fails rather than the session.
    ///
    /// Core and exec types belong to the generation-1 baseline; they work on
    /// every runtime we still talk to, including the pre-0.5 legacy one.
    /// Filesystem streaming did not exist in the pre-0.5 legacy protocol
    /// (generation 1), so the `Fs*` types require generation 2 or newer.
    /// TCP forwarding was introduced in generation 4. `core.error` was
    /// introduced in generation 5. Reachability checks and explicit idle
    /// refreshes were introduced in generation 6.
    ///
    /// There is deliberately no wildcard arm: adding a new `MessageType` must
    /// force a conscious choice of the generation that introduced it (and a
    /// matching `PROTOCOL_VERSION` bump). Message types are append-only — never
    /// lower or re-purpose an existing value.
    pub fn min_protocol_version(&self) -> u8 {
        match self {
            Self::Ready
            | Self::InitResolved
            | Self::InitAck
            | Self::Shutdown
            | Self::RelayClientDisconnected
            | Self::ClockSync
            | Self::ExecRequest
            | Self::ExecStarted
            | Self::ExecStdin
            | Self::ExecStdinError
            | Self::ExecStdout
            | Self::ExecStderr
            | Self::ExecExited
            | Self::ExecFailed
            | Self::ExecResize
            | Self::ExecSignal => 1,
            Self::FsRequest | Self::FsResponse | Self::FsData => 2,
            Self::CoreError => 5,
            Self::Ping | Self::Pong | Self::Touch | Self::Touched => 6,
            Self::TcpConnect
            | Self::TcpConnected
            | Self::TcpData
            | Self::TcpEof
            | Self::TcpClose
            | Self::TcpClosed
            | Self::TcpFailed => 4,
        }
    }

    /// Whether a peer that speaks `peer_generation` is new enough to handle this
    /// message type.
    ///
    /// The shared version-compatibility primitive for both directions. The host
    /// gates its sends on it (`AgentClient::ensure_version_compat`); the guest
    /// can gate a guest-initiated message the same way, reading the peer's
    /// generation from the `v` field of the request that established the session.
    /// See `VERSIONING.md`.
    pub fn is_available_at(&self, peer_generation: u8) -> bool {
        self.min_protocol_version() <= peer_generation
    }

    /// Returns the wire string representation.
    ///
    /// Backed by the per-variant `#[strum(serialize = ...)]` attribute, the
    /// single source of truth for wire strings.
    pub fn as_str(&self) -> &'static str {
        (*self).into()
    }

    /// Parses a wire string into a message type, the inverse of
    /// [`as_str`](Self::as_str). Returns `None` for an unknown string.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_wire_str(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown message type: {s}")))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        let types = [
            (MessageType::Ready, "core.ready"),
            (MessageType::InitResolved, "core.init.resolved"),
            (MessageType::InitAck, "core.init.ack"),
            (MessageType::Shutdown, "core.shutdown"),
            (
                MessageType::RelayClientDisconnected,
                "core.relay.client.disconnected",
            ),
            (MessageType::ClockSync, "core.clock.sync"),
            (MessageType::Ping, "core.ping"),
            (MessageType::Pong, "core.pong"),
            (MessageType::Touch, "core.touch"),
            (MessageType::Touched, "core.touched"),
            (MessageType::CoreError, "core.error"),
            (MessageType::ExecRequest, "core.exec.request"),
            (MessageType::ExecStarted, "core.exec.started"),
            (MessageType::ExecStdin, "core.exec.stdin"),
            (MessageType::ExecStdinError, "core.exec.stdin.error"),
            (MessageType::ExecStdout, "core.exec.stdout"),
            (MessageType::ExecStderr, "core.exec.stderr"),
            (MessageType::ExecExited, "core.exec.exited"),
            (MessageType::ExecFailed, "core.exec.failed"),
            (MessageType::ExecResize, "core.exec.resize"),
            (MessageType::ExecSignal, "core.exec.signal"),
            (MessageType::FsRequest, "core.fs.request"),
            (MessageType::FsResponse, "core.fs.response"),
            (MessageType::FsData, "core.fs.data"),
            (MessageType::TcpConnect, "core.tcp.connect"),
            (MessageType::TcpConnected, "core.tcp.connected"),
            (MessageType::TcpData, "core.tcp.data"),
            (MessageType::TcpEof, "core.tcp.eof"),
            (MessageType::TcpClose, "core.tcp.close"),
            (MessageType::TcpClosed, "core.tcp.closed"),
            (MessageType::TcpFailed, "core.tcp.failed"),
        ];

        for (mt, expected_str) in &types {
            assert_eq!(mt.as_str(), *expected_str);
            assert_eq!(MessageType::from_wire_str(expected_str).unwrap(), *mt);
        }
    }

    #[test]
    fn test_message_type_serde_roundtrip() {
        let types = [
            MessageType::Ready,
            MessageType::InitResolved,
            MessageType::InitAck,
            MessageType::Shutdown,
            MessageType::RelayClientDisconnected,
            MessageType::ClockSync,
            MessageType::Ping,
            MessageType::Pong,
            MessageType::Touch,
            MessageType::Touched,
            MessageType::CoreError,
            MessageType::ExecRequest,
            MessageType::ExecStarted,
            MessageType::ExecStdin,
            MessageType::ExecStdinError,
            MessageType::ExecStdout,
            MessageType::ExecStderr,
            MessageType::ExecExited,
            MessageType::ExecFailed,
            MessageType::ExecResize,
            MessageType::ExecSignal,
            MessageType::FsRequest,
            MessageType::FsResponse,
            MessageType::FsData,
            MessageType::TcpConnect,
            MessageType::TcpConnected,
            MessageType::TcpData,
            MessageType::TcpEof,
            MessageType::TcpClose,
            MessageType::TcpClosed,
            MessageType::TcpFailed,
        ];

        for mt in &types {
            let mut buf = Vec::new();
            ciborium::into_writer(mt, &mut buf).unwrap();
            let decoded: MessageType = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(&decoded, mt);
        }
    }

    #[test]
    fn test_unknown_message_type() {
        assert!(MessageType::from_wire_str("core.unknown").is_none());
    }

    #[test]
    fn test_message_with_payload_roundtrip() {
        use crate::exec::ExecExited;

        let msg =
            Message::with_payload(MessageType::ExecExited, 7, &ExecExited { code: 42 }).unwrap();

        assert_eq!(msg.t, MessageType::ExecExited);
        assert_eq!(msg.id, 7);
        assert_eq!(msg.flags, FLAG_TERMINAL);

        let payload: ExecExited = msg.payload().unwrap();
        assert_eq!(payload.code, 42);
    }

    #[test]
    fn test_message_type_flags() {
        assert_eq!(MessageType::ExecExited.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::ExecFailed.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::FsResponse.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::TcpClosed.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::TcpFailed.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::Pong.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::Touched.flags(), FLAG_TERMINAL);
        assert_eq!(MessageType::ExecRequest.flags(), FLAG_SESSION_START);
        assert_eq!(MessageType::FsRequest.flags(), FLAG_SESSION_START);
        assert_eq!(MessageType::TcpConnect.flags(), FLAG_SESSION_START);
        assert_eq!(MessageType::Ready.flags(), 0);
        assert_eq!(MessageType::InitResolved.flags(), 0);
        assert_eq!(MessageType::InitAck.flags(), 0);
        assert_eq!(MessageType::Shutdown.flags(), FLAG_SHUTDOWN);
        assert_eq!(MessageType::ClockSync.flags(), 0);
        assert_eq!(MessageType::Ping.flags(), 0);
        assert_eq!(MessageType::Touch.flags(), 0);
        assert_eq!(MessageType::ExecStarted.flags(), 0);
        assert_eq!(MessageType::ExecStdin.flags(), 0);
        assert_eq!(MessageType::ExecStdout.flags(), 0);
        assert_eq!(MessageType::ExecStderr.flags(), 0);
        assert_eq!(MessageType::ExecResize.flags(), 0);
        assert_eq!(MessageType::ExecSignal.flags(), 0);
        assert_eq!(MessageType::FsData.flags(), 0);
        assert_eq!(MessageType::TcpConnected.flags(), 0);
        assert_eq!(MessageType::TcpData.flags(), 0);
        assert_eq!(MessageType::TcpEof.flags(), 0);
        assert_eq!(MessageType::TcpClose.flags(), 0);
    }

    #[test]
    fn test_additive_fields_keep_old_and_new_compatible() {
        // The core backward-compatibility guarantee from VERSIONING.md: a new,
        // always-optional field is safe in both directions across a version skew.
        use serde::{Deserialize, Serialize};

        // A payload as it existed at an older generation.
        #[derive(Serialize, Deserialize)]
        struct Old {
            a: u32,
            b: u32,
        }

        // The same payload after a later generation added `c` (optional).
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct New {
            a: u32,
            b: u32,
            #[serde(default)]
            c: u32,
        }

        // New sender -> old receiver: the unknown `c` is ignored, not an error.
        let mut new_bytes = Vec::new();
        ciborium::into_writer(&New { a: 1, b: 2, c: 3 }, &mut new_bytes).unwrap();
        let as_old: Old = ciborium::from_reader(&new_bytes[..]).unwrap();
        assert_eq!((as_old.a, as_old.b), (1, 2));

        // Old sender -> new receiver: the missing `c` falls back to its default.
        let mut old_bytes = Vec::new();
        ciborium::into_writer(&Old { a: 1, b: 2 }, &mut old_bytes).unwrap();
        let as_new: New = ciborium::from_reader(&old_bytes[..]).unwrap();
        assert_eq!(as_new, New { a: 1, b: 2, c: 0 });
    }

    #[test]
    fn test_is_available_at() {
        // Exec is in the generation-1 baseline: available to every peer.
        assert!(MessageType::ExecRequest.is_available_at(1));
        assert!(MessageType::ExecRequest.is_available_at(2));
        assert!(MessageType::ExecRequest.is_available_at(PROTOCOL_VERSION));
        // Filesystem requires generation 2: unavailable to a legacy (gen 1) peer.
        assert!(!MessageType::FsRequest.is_available_at(1));
        assert!(MessageType::FsRequest.is_available_at(2));
        assert!(MessageType::FsRequest.is_available_at(PROTOCOL_VERSION));
        // Ping/touch are generation-6 core capabilities.
        assert!(!MessageType::Ping.is_available_at(5));
        assert!(MessageType::Ping.is_available_at(6));
        assert!(MessageType::Ping.is_available_at(PROTOCOL_VERSION));
    }

    #[test]
    fn test_min_protocol_version_per_type() {
        // Core and exec types are the generation-1 baseline: usable on every
        // runtime we still talk to, including the pre-0.5 legacy one.
        let baseline = [
            MessageType::Ready,
            MessageType::InitResolved,
            MessageType::InitAck,
            MessageType::Shutdown,
            MessageType::RelayClientDisconnected,
            MessageType::ClockSync,
            MessageType::ExecRequest,
            MessageType::ExecStarted,
            MessageType::ExecStdin,
            MessageType::ExecStdinError,
            MessageType::ExecStdout,
            MessageType::ExecStderr,
            MessageType::ExecExited,
            MessageType::ExecFailed,
            MessageType::ExecResize,
            MessageType::ExecSignal,
        ];
        for mt in &baseline {
            assert_eq!(mt.min_protocol_version(), 1, "{mt:?} should be v1 baseline");
        }

        // Filesystem streaming did not exist in the pre-0.5 legacy protocol, so
        // these require a post-legacy generation.
        for mt in [
            MessageType::FsRequest,
            MessageType::FsResponse,
            MessageType::FsData,
        ] {
            assert_eq!(mt.min_protocol_version(), 2, "{mt:?} should require gen 2");
        }

        for mt in [
            MessageType::Ping,
            MessageType::Pong,
            MessageType::Touch,
            MessageType::Touched,
        ] {
            assert_eq!(mt.min_protocol_version(), 6, "{mt:?} should require gen 6");
        }

        // Every current type must be sendable to a current peer.
        assert!(MessageType::FsRequest.min_protocol_version() <= PROTOCOL_VERSION);
    }

    #[test]
    fn test_message_new_computes_flags() {
        let msg = Message::new(MessageType::ExecRequest, 1, Vec::new());
        assert_eq!(msg.flags, FLAG_SESSION_START);

        let msg = Message::new(MessageType::ExecStdout, 1, Vec::new());
        assert_eq!(msg.flags, 0);
    }
}
