//! Configured MSBS setup over the shared framed client.

use std::sync::Arc;

use microsandbox_protocol::{
    codec::{self, RawFrame},
    message::FLAG_TERMINAL,
    supervisor::{
        DEFAULT_SUPERVISOR_REQUEST_TIMEOUT, DEFAULT_SUPERVISOR_SETUP_TIMEOUT,
        MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE, SUPERVISOR_HANDSHAKE_GENERATION, SUPERVISOR_MAGIC,
        SupervisorError, SupervisorHello, SupervisorWelcome, supervisor_message_min_generation,
    },
    wire::Envelope,
};
use microsandbox_protocol_client::{
    BoxFuture, BoxTransport, CborEnvelopeCodec, ClientError, ClientResult, ConnectOptions,
    ErrorKind, Established, IdRange, Protocol, SendMetadata,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Marker used by the generic router after configured supervisor setup.
pub struct SupervisorProtocol;

/// Negotiated supervisor metadata and exact welcome frame.
#[derive(Debug)]
pub struct SupervisorReady {
    /// Peer-selected generation, identity, and catalog position.
    pub welcome: SupervisorWelcome,
    /// Original welcome frame, including unknown envelope fields.
    pub frame: RawFrame,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorProtocol {
    /// Establish MSBS using caller-owned identity and home configuration.
    pub async fn establish_configured(
        mut stream: BoxTransport,
        mut options: ConnectOptions,
        hello: SupervisorHello,
    ) -> ClientResult<Established<SupervisorReady>> {
        hello
            .validate()
            .map_err(|_| ClientError::new(ErrorKind::InvalidOptions))?;
        stream.write_all(SUPERVISOR_MAGIC).await?;
        let opening = Envelope::new(SUPERVISOR_HANDSHAKE_GENERATION, "supervisor.hello", &hello)?
            .frame(0, 0)?;
        if opening.body.len() + 5 > MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE as usize {
            return Err(ClientError::new(ErrorKind::InvalidOptions));
        }
        codec::write_raw_frame(&mut stream, &opening)
            .await
            .map_err(|error| match error {
                microsandbox_protocol::ProtocolError::Io(error) => ClientError::from(error),
                _ => ClientError::new(ErrorKind::InvalidData),
            })?;

        // Bound the peer-controlled allocation before reading the remainder.
        let length = stream.read_u32().await?;
        if !(5..=MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE).contains(&length) {
            return Err(ClientError::new(ErrorKind::InvalidData));
        }
        let id = stream.read_u32().await?;
        let flags = stream.read_u8().await?;
        let mut body = vec![0; length as usize - 5];
        stream.read_exact(&mut body).await?;
        let frame = RawFrame { id, flags, body };
        let envelope = Envelope::decode(&frame.body)?;
        if frame.id != 0
            || frame.flags != FLAG_TERMINAL
            || envelope.v != SUPERVISOR_HANDSHAKE_GENERATION
        {
            return Err(ClientError::new(ErrorKind::InvalidData));
        }
        if envelope.t == "supervisor.error" {
            let refusal: SupervisorError = envelope.payload()?;
            let kind = if refusal.code == "unsupported_generation" {
                ErrorKind::UnsupportedOperation
            } else {
                ErrorKind::InvalidData
            };
            return Err(ClientError::new(kind));
        }
        if envelope.t != "supervisor.welcome" {
            return Err(ClientError::new(ErrorKind::InvalidData));
        }
        let welcome: SupervisorWelcome = envelope.payload()?;
        welcome
            .validate_for(&hello)
            .map_err(|_| ClientError::new(ErrorKind::InvalidData))?;

        options.limits.max_frame_size = welcome.effective_limits.max_frame_size;
        options.limits.max_in_flight = welcome.effective_limits.max_in_flight as usize;
        options
            .limits
            .incomplete_frame_timeout
            .get_or_insert(DEFAULT_SUPERVISOR_SETUP_TIMEOUT);
        options
            .limits
            .request_timeout
            .get_or_insert(DEFAULT_SUPERVISOR_REQUEST_TIMEOUT);
        Ok(Established {
            transport: stream,
            codec: Arc::new(CborEnvelopeCodec),
            ids: IdRange {
                start: 1,
                end_exclusive: 1u64 << 32,
            },
            ready: SupervisorReady { welcome, frame },
            limits: options.limits,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Protocol for SupervisorProtocol {
    type Ready = SupervisorReady;

    fn establish(
        _stream: BoxTransport,
        _options: ConnectOptions,
    ) -> BoxFuture<'static, ClientResult<Established<Self::Ready>>> {
        // A valid hello requires caller identity and a canonical-home digest.
        // SupervisorClient is therefore the only supported connection entry point.
        Box::pin(async { Err(ClientError::new(ErrorKind::InvalidOptions)) })
    }

    fn prepare(ready: &Self::Ready, wire_name: &str) -> ClientResult<SendMetadata> {
        if matches!(wire_name, "supervisor.hello" | "supervisor.welcome") {
            return Err(ClientError::new(ErrorKind::UnsupportedOperation));
        }
        if supervisor_message_min_generation(wire_name)
            .is_some_and(|minimum| minimum > ready.welcome.generation)
        {
            return Err(ClientError::new(ErrorKind::UnsupportedOperation));
        }
        Ok(SendMetadata {
            generation: ready.welcome.generation,
            flags: 0,
        })
    }
}
