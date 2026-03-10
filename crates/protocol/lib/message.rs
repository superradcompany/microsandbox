//! Message envelope and type definitions for the agent protocol.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::ProtocolResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The message envelope sent over the wire.
///
/// Each message contains a version, type, correlation ID, and a CBOR payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Protocol version.
    pub v: u8,

    /// Message type.
    pub t: MessageType,

    /// Correlation ID used to associate requests with responses and
    /// to identify exec sessions.
    pub id: u32,

    /// The CBOR-encoded payload bytes.
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
}

/// Identifies the type of a protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Guest agent is ready.
    Ready,

    /// Host requests shutdown.
    Shutdown,

    /// Host requests command execution.
    ExecRequest,

    /// Guest confirms command started.
    ExecStarted,

    /// Host sends stdin data.
    ExecStdin,

    /// Guest sends stdout data.
    ExecStdout,

    /// Guest sends stderr data.
    ExecStderr,

    /// Guest reports command exit.
    ExecExited,

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
        Self {
            v: PROTOCOL_VERSION,
            t,
            id,
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
        Ok(Self {
            v: PROTOCOL_VERSION,
            t,
            id,
            p,
        })
    }

    /// Deserializes the payload bytes into the given type.
    pub fn payload<T: DeserializeOwned>(&self) -> ProtocolResult<T> {
        Ok(ciborium::from_reader(&self.p[..])?)
    }
}

impl MessageType {
    /// Returns the wire string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "core.ready",
            Self::Shutdown => "core.shutdown",
            Self::ExecRequest => "core.exec.request",
            Self::ExecStarted => "core.exec.started",
            Self::ExecStdin => "core.exec.stdin",
            Self::ExecStdout => "core.exec.stdout",
            Self::ExecStderr => "core.exec.stderr",
            Self::ExecExited => "core.exec.exited",
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
            "core.shutdown" => Some(Self::Shutdown),
            "core.exec.request" => Some(Self::ExecRequest),
            "core.exec.started" => Some(Self::ExecStarted),
            "core.exec.stdin" => Some(Self::ExecStdin),
            "core.exec.stdout" => Some(Self::ExecStdout),
            "core.exec.stderr" => Some(Self::ExecStderr),
            "core.exec.exited" => Some(Self::ExecExited),
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
            (MessageType::Shutdown, "core.shutdown"),
            (MessageType::ExecRequest, "core.exec.request"),
            (MessageType::ExecStarted, "core.exec.started"),
            (MessageType::ExecStdin, "core.exec.stdin"),
            (MessageType::ExecStdout, "core.exec.stdout"),
            (MessageType::ExecStderr, "core.exec.stderr"),
            (MessageType::ExecExited, "core.exec.exited"),
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
            MessageType::Shutdown,
            MessageType::ExecRequest,
            MessageType::ExecStarted,
            MessageType::ExecStdin,
            MessageType::ExecStdout,
            MessageType::ExecStderr,
            MessageType::ExecExited,
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

        let payload: ExecExited = msg.payload().unwrap();
        assert_eq!(payload.code, 42);
    }
}
