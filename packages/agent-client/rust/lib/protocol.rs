//! Agent relay setup and metadata over the shared framed router.

use std::sync::Arc;

use microsandbox_protocol::{
    codec::{self, MAX_FRAME_SIZE, RawFrame},
    core::Ready,
    message::{FRAME_HEADER_SIZE, MessageType, PROTOCOL_VERSION},
};
use microsandbox_protocol_client::{
    BoxFuture, BoxTransport, CborEnvelopeCodec, ClientError, ClientResult, ConnectOptions,
    ErrorKind, Established, IdRange, Protocol, SendMetadata,
};
use tokio::io::AsyncReadExt;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Protocol generation used by the supported pre-0.5 agent wire path.
pub const LEGACY_PROTOCOL_VERSION: u8 = 1;
const LEGACY_RELAY_ID_RANGE_STEP: u32 = u32::MAX / 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Agent relay protocol specialization; it owns no router or SDK services.
pub struct AgentProtocol;

/// Wire form selected from the relay prologue, separate from capability gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentWireFormat {
    /// Current relay prologue and envelope generation.
    Current,
    /// Supported pre-0.5 relay prologue and generation-one envelope.
    LegacyV1,
}

/// Immutable metadata captured once during relay setup.
#[derive(Debug, Clone)]
pub struct AgentReady {
    /// Relay wire form selected during the prologue.
    pub wire_format: AgentWireFormat,
    /// Smaller of host and peer generations, used for known-operation gates.
    pub negotiated_version: u8,
    /// Decoded original `core.ready` payload.
    pub agent: Ready,
    ready_body: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentWireFormat {
    /// Envelope generation emitted on this wire form.
    ///
    /// Current peers historically receive the host generation even when the
    /// feature gate negotiated lower; preserve that existing byte contract.
    pub fn version(self) -> u8 {
        match self {
            Self::Current => PROTOCOL_VERSION,
            Self::LegacyV1 => LEGACY_PROTOCOL_VERSION,
        }
    }
}

impl AgentReady {
    /// Exact original ready envelope, including unknown fields.
    pub fn ready_bytes(&self) -> &[u8] {
        &self.ready_body
    }

    /// Whether the connected generation supports this known message.
    pub fn supports(&self, message_type: MessageType) -> bool {
        message_type.is_available_at(self.negotiated_version)
    }

    /// Self-reported package version, empty on older agents lacking the field.
    pub fn agent_version(&self) -> &str {
        &self.agent.agent_version
    }

    /// Whether the connection selected the supported pre-0.5 wire form.
    pub fn is_legacy_protocol(&self) -> bool {
        self.wire_format == AgentWireFormat::LegacyV1
    }
}

impl AgentProtocol {
    /// Validate a known operation against a separately retained generation.
    pub fn ensure_version_compat_for(
        message_type: MessageType,
        negotiated: u8,
    ) -> ClientResult<()> {
        if message_type.is_available_at(negotiated) {
            Ok(())
        } else {
            Err(ClientError::new(ErrorKind::UnsupportedOperation))
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Protocol for AgentProtocol {
    // The generation-eight relay permanently retires completed correlations.
    const REUSE_IDS: bool = false;
    type Ready = AgentReady;

    fn establish(
        mut stream: BoxTransport,
        options: ConnectOptions,
    ) -> BoxFuture<'static, ClientResult<Established<AgentReady>>> {
        Box::pin(async move {
            // The engine bounds this entire future with one setup deadline.
            // Eight bytes disambiguate current [min,max] and legacy [offset,len].
            let mut prologue = [0u8; 8];
            stream.read_exact(&mut prologue).await?;
            let first = u32::from_be_bytes(prologue[..4].try_into().unwrap());
            let second = u32::from_be_bytes(prologue[4..].try_into().unwrap());
            let legacy = (FRAME_HEADER_SIZE as u32..=MAX_FRAME_SIZE).contains(&second)
                && (first == 0 || first >= second);
            let (ids, frame, wire_format) = if legacy {
                let frame = read_after_prefix(&mut stream, second).await?;
                (
                    IdRange {
                        start: first.saturating_add(1),
                        end_exclusive: first.saturating_add(LEGACY_RELAY_ID_RANGE_STEP).into(),
                    },
                    frame,
                    AgentWireFormat::LegacyV1,
                )
            } else {
                // Current ranges can start at zero, but ID zero is setup-only.
                let ids = IdRange {
                    start: first.max(1),
                    end_exclusive: second.into(),
                };
                ids.validate()?;
                let frame = codec::read_raw_frame(&mut stream)
                    .await
                    .map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
                (ids, frame, AgentWireFormat::Current)
            };
            ids.validate()?;
            // Keep the historical ready decoder and feature-generation rule.
            let ready_message = codec::raw_frame_to_message(frame.clone())
                .map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
            if ready_message.t != MessageType::Ready {
                return Err(ClientError::new(ErrorKind::InvalidData));
            }
            let agent = ready_message
                .payload::<Ready>()
                .map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
            let ready = AgentReady {
                wire_format,
                negotiated_version: wire_format.version().min(ready_message.v),
                agent,
                ready_body: frame.body,
            };
            if ready.is_legacy_protocol() {
                tracing::warn!(
                    "agent client: legacy pre-0.5 exec protocol; filesystem operations require a newer agent"
                );
            }
            Ok(Established {
                transport: stream,
                codec: Arc::new(CborEnvelopeCodec),
                ids,
                ready,
                limits: options.limits,
            })
        })
    }

    fn prepare(ready: &AgentReady, wire_name: &str) -> ClientResult<SendMetadata> {
        let flags = match MessageType::from_wire_str(wire_name) {
            Some(message_type) => {
                Self::ensure_version_compat_for(message_type, ready.negotiated_version)?;
                message_type.flags()
            }
            // Dynamic names need no schema registration. Raw sends also support
            // caller-selected flags and generations.
            None => 0,
        };
        Ok(SendMetadata {
            generation: ready.wire_format.version(),
            flags,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn read_after_prefix(stream: &mut BoxTransport, length: u32) -> ClientResult<RawFrame> {
    if !(FRAME_HEADER_SIZE as u32..=MAX_FRAME_SIZE).contains(&length) {
        return Err(ClientError::new(ErrorKind::InvalidData));
    }
    let mut header = [0u8; FRAME_HEADER_SIZE];
    stream.read_exact(&mut header).await?;
    let mut body = vec![0; length as usize - FRAME_HEADER_SIZE];
    stream.read_exact(&mut body).await?;
    Ok(RawFrame {
        id: u32::from_be_bytes(header[..4].try_into().unwrap()),
        flags: header[4],
        body,
    })
}
