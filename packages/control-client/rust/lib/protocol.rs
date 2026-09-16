//! Framed control setup. This path never probes or falls back to JSON.

use std::sync::Arc;

use microsandbox_protocol::{
    codec::{self, RawFrame},
    control::{
        CONTROL_GENERATION, ControlError, ControlHello, ControlWelcome, DEFAULT_MAX_IN_FLIGHT,
        DEFAULT_REQUEST_TIMEOUT, DEFAULT_SETUP_TIMEOUT, MAX_HANDSHAKE_FRAME_SIZE,
    },
    wire::Envelope,
};
use microsandbox_protocol_client::{
    BoxFuture, BoxTransport, CborEnvelopeCodec, Client, ClientError, ClientResult, ConnectOptions,
    ErrorKind, Established, IdRange, Protocol, SendMetadata,
};
use tokio::io::AsyncReadExt;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Always-framed host control, including the full generic low-level surface.
pub type ControlClient = Client<ControlProtocol>;

/// Generation-one hello/welcome and operation metadata.
pub struct ControlProtocol;

/// Negotiated limits and the exact original welcome envelope.
#[derive(Debug, Clone)]
pub struct ControlReady {
    /// Peer-selected generation and application ceilings.
    pub welcome: ControlWelcome,
    /// Original frame, including unknown envelope fields.
    pub frame: RawFrame,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Protocol for ControlProtocol {
    type Ready = ControlReady;

    fn establish(
        mut stream: BoxTransport,
        options: ConnectOptions,
    ) -> BoxFuture<'static, ClientResult<Established<Self::Ready>>> {
        Box::pin(async move {
            let hello = ControlHello {
                max_frame_size: options.limits.max_frame_size,
                max_in_flight: options
                    .limits
                    .max_in_flight
                    .min(DEFAULT_MAX_IN_FLIGHT as usize) as u32,
                ..Default::default()
            };
            hello
                .validate()
                .map_err(|_| ClientError::new(ErrorKind::InvalidOptions))?;
            let opening =
                Envelope::new(CONTROL_GENERATION, "control.hello", &hello)?.frame(0, 0)?;
            codec::write_raw_frame(&mut stream, &opening)
                .await
                .map_err(|error| match error {
                    microsandbox_protocol::ProtocolError::Io(error) => ClientError::from(error),
                    _ => ClientError::new(ErrorKind::InvalidData),
                })?;
            // Setup is already inside the engine's one total deadline. Bound
            // allocation from the opening prefix before reading any body.
            let length = stream.read_u32().await?;
            if !(5..=MAX_HANDSHAKE_FRAME_SIZE).contains(&length) {
                return Err(ClientError::new(ErrorKind::InvalidData));
            }
            let id = stream.read_u32().await?;
            let flags = stream.read_u8().await?;
            let mut body = vec![0; length as usize - 5];
            stream.read_exact(&mut body).await?;
            let frame = RawFrame { id, flags, body };
            let envelope = Envelope::decode(&frame.body)?;
            if frame.id != 0 || frame.flags != 1 || envelope.v != CONTROL_GENERATION {
                return Err(ClientError::new(ErrorKind::InvalidData));
            }
            if envelope.t == "control.error" {
                let refusal: ControlError = envelope.payload()?;
                let kind = if refusal.code == "unsupported_generation" {
                    ErrorKind::UnsupportedOperation
                } else {
                    ErrorKind::InvalidData
                };
                return Err(ClientError::new(kind));
            }
            if envelope.t != "control.welcome" {
                return Err(ClientError::new(ErrorKind::InvalidData));
            }
            let welcome: ControlWelcome = envelope.payload()?;
            welcome
                .validate_for(&hello)
                .map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
            let mut limits = options.limits;
            limits.max_frame_size = welcome.max_frame_size;
            limits.max_in_flight = welcome.max_in_flight as usize;
            limits
                .incomplete_frame_timeout
                .get_or_insert(DEFAULT_SETUP_TIMEOUT);
            limits
                .request_timeout
                .get_or_insert(DEFAULT_REQUEST_TIMEOUT);
            Ok(Established {
                transport: stream,
                codec: Arc::new(CborEnvelopeCodec),
                ids: IdRange {
                    start: 1,
                    end_exclusive: 1u64 << 32,
                },
                ready: ControlReady { welcome, frame },
                limits,
            })
        })
    }

    fn prepare(ready: &Self::Ready, wire_name: &str) -> ClientResult<SendMetadata> {
        // Setup messages cannot be sent as ordinary named operations. Unknown
        // extensions remain possible; raw callers can inspect any wire shape.
        if matches!(wire_name, "control.hello" | "control.welcome") {
            return Err(ClientError::new(ErrorKind::UnsupportedOperation));
        }
        Ok(SendMetadata {
            generation: ready.welcome.generation,
            flags: 0,
        })
    }
}
