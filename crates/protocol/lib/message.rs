//! Message envelope and type definitions for the agent protocol.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::ProtocolResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 3;

/// Frame flag: this is the last message for the given correlation ID.
///
/// Set on terminal message types such as `ExecExited` and `FsResponse`.
pub const FLAG_TERMINAL: u8 = 0b0000_0001;

/// Frame flag: this is the first message of a new session.
///
/// Set on session-initiating message types such as `ExecRequest` and `FsRequest`.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Guest agent is ready.
    Ready,

    /// Guest reports init context before user mounts.
    InitResolved,

    /// Host acknowledges init-context setup.
    InitAck,

    /// Host requests shutdown.
    Shutdown,

    /// Host relay reports that one SDK client disconnected.
    RelayClientDisconnected,

    /// Host asks the guest to synchronize `CLOCK_REALTIME`.
    ClockSync,

    /// Host requests command execution.
    ExecRequest,

    /// Guest confirms command started.
    ExecStarted,

    /// Host sends stdin data.
    ExecStdin,

    /// Guest reports that a prior `ExecStdin` write to the child's
    /// stdin failed (e.g. the child closed its read end). Non-terminal:
    /// the session continues and may still produce stdout/stderr and
    /// an exit code.
    ExecStdinError,

    /// Guest sends stdout data.
    ExecStdout,

    /// Guest sends stderr data.
    ExecStderr,

    /// Guest reports command exit.
    ExecExited,

    /// Guest reports command failed to spawn (binary not found,
    /// permission denied, etc.). Distinct from `ExecExited` —
    /// `ExecFailed` means the user code never ran. Terminal.
    ExecFailed,

    /// Host requests PTY resize.
    ExecResize,

    /// Host sends signal to process.
    ExecSignal,

    /// Host requests a filesystem operation.
    FsRequest,

    /// Guest sends a terminal filesystem response.
    FsResponse,

    /// Streaming file data chunk (bidirectional).
    FsData,
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
            Self::ExecExited | Self::ExecFailed | Self::FsResponse => FLAG_TERMINAL,
            Self::ExecRequest | Self::FsRequest => FLAG_SESSION_START,
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
        }
    }

    /// Returns the wire string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "core.ready",
            Self::InitResolved => "core.init.resolved",
            Self::InitAck => "core.init.ack",
            Self::Shutdown => "core.shutdown",
            Self::RelayClientDisconnected => "core.relay.client.disconnected",
            Self::ClockSync => "core.clock.sync",
            Self::ExecRequest => "core.exec.request",
            Self::ExecStarted => "core.exec.started",
            Self::ExecStdin => "core.exec.stdin",
            Self::ExecStdinError => "core.exec.stdin.error",
            Self::ExecStdout => "core.exec.stdout",
            Self::ExecStderr => "core.exec.stderr",
            Self::ExecExited => "core.exec.exited",
            Self::ExecFailed => "core.exec.failed",
            Self::ExecResize => "core.exec.resize",
            Self::ExecSignal => "core.exec.signal",
            Self::FsRequest => "core.fs.request",
            Self::FsResponse => "core.fs.response",
            Self::FsData => "core.fs.data",
        }
    }

    /// Parses a wire string into a message type.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "core.ready" => Some(Self::Ready),
            "core.init.resolved" => Some(Self::InitResolved),
            "core.init.ack" => Some(Self::InitAck),
            "core.shutdown" => Some(Self::Shutdown),
            "core.relay.client.disconnected" => Some(Self::RelayClientDisconnected),
            "core.clock.sync" => Some(Self::ClockSync),
            "core.exec.request" => Some(Self::ExecRequest),
            "core.exec.started" => Some(Self::ExecStarted),
            "core.exec.stdin" => Some(Self::ExecStdin),
            "core.exec.stdin.error" => Some(Self::ExecStdinError),
            "core.exec.stdout" => Some(Self::ExecStdout),
            "core.exec.stderr" => Some(Self::ExecStderr),
            "core.exec.exited" => Some(Self::ExecExited),
            "core.exec.failed" => Some(Self::ExecFailed),
            "core.exec.resize" => Some(Self::ExecResize),
            "core.exec.signal" => Some(Self::ExecSignal),
            "core.fs.request" => Some(Self::FsRequest),
            "core.fs.response" => Some(Self::FsResponse),
            "core.fs.data" => Some(Self::FsData),
            _ => None,
        }
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
        assert_eq!(MessageType::ExecRequest.flags(), FLAG_SESSION_START);
        assert_eq!(MessageType::FsRequest.flags(), FLAG_SESSION_START);
        assert_eq!(MessageType::Ready.flags(), 0);
        assert_eq!(MessageType::InitResolved.flags(), 0);
        assert_eq!(MessageType::InitAck.flags(), 0);
        assert_eq!(MessageType::Shutdown.flags(), FLAG_SHUTDOWN);
        assert_eq!(MessageType::ClockSync.flags(), 0);
        assert_eq!(MessageType::ExecStarted.flags(), 0);
        assert_eq!(MessageType::ExecStdin.flags(), 0);
        assert_eq!(MessageType::ExecStdout.flags(), 0);
        assert_eq!(MessageType::ExecStderr.flags(), 0);
        assert_eq!(MessageType::ExecResize.flags(), 0);
        assert_eq!(MessageType::ExecSignal.flags(), 0);
        assert_eq!(MessageType::FsData.flags(), 0);
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
