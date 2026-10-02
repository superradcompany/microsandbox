//! Legacy unary exchanges: one real JSON operation per independently owned stream.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::control::{ControlRequest, DEFAULT_REQUEST_TIMEOUT};
use microsandbox_protocol_client::{
    ClientError, ConnectOptions, Connector, Delivery, ErrorKind, LocalConnector, RequestOptions,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    CheckedControlRequest, CompatibleControlRequest, ControlClientError, ControlClientResult,
    ControlMode, IntoControlMessage, JsonReply, dialer::Dialer,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bound applies to new-client discovery replies, not legacy request lines.
pub const MAX_DISCOVERY_RESPONSE_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Explicit JSON adapter. Construction is inert; every call opens one stream.
#[derive(Clone)]
pub struct JsonControlClient {
    pub(crate) dialer: Dialer,
    pub(crate) options: ConnectOptions,
    closed: CancellationToken,
    rediscover: Option<ControlMode>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JsonControlClient {
    /// Select legacy JSON explicitly, without probing or opening a connection.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self::from_connector(Arc::new(LocalConnector::new(path)))
    }

    /// Store a repeatable dialer without I/O or hidden negotiation.
    pub fn from_connector(connector: Arc<dyn Connector>) -> Self {
        Self::configured(
            Dialer::Unverified(connector),
            ConnectOptions::default(),
            None,
        )
    }

    /// Configure local deadlines without performing I/O.
    pub fn from_connector_with(
        connector: Arc<dyn Connector>,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ControlClientResult<Self> {
        let options = configure(ConnectOptions::default());
        options.limits.validate()?;
        Ok(Self::configured(
            Dialer::Unverified(connector),
            options,
            None,
        ))
    }

    pub(crate) fn configured(
        dialer: Dialer,
        options: ConnectOptions,
        rediscover: Option<ControlMode>,
    ) -> Self {
        Self {
            dialer,
            options,
            closed: CancellationToken::new(),
            rediscover,
        }
    }

    /// Inspect shared closure, including unexpected exchange failure.
    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    /// Wait for shared closure. Successful per-operation JSON EOF is not a
    /// session closure; explicit close or an unexpected exchange failure is.
    pub async fn closed(&self) {
        self.closed.cancelled().await;
    }

    /// Close every clone and wake each outstanding exchange with its own
    /// admission certainty. No implicit reconnect follows an explicit close.
    pub async fn close(&self) {
        self.closed.cancel();
    }

    /// Translate a known native request, returning its actual JSON reply.
    pub async fn request(
        &self,
        message: impl IntoControlMessage,
    ) -> ControlClientResult<JsonReply> {
        self.request_with(message, |options| options).await
    }

    /// Configure one total attempt deadline, including dial and any discovery.
    pub async fn request_with(
        &self,
        message: impl IntoControlMessage,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ControlClientResult<JsonReply> {
        let request = message.into_json()?;
        self.operation(request, configure(RequestOptions::default()))
            .await
    }

    /// Normalize a checked operation without manufacturing a CBOR response.
    pub async fn request_typed<R: CheckedControlRequest>(
        &self,
        request: &R,
    ) -> ControlClientResult<R::Response> {
        self.request_typed_with(request, |options| options).await
    }

    /// Configure one checked unary attempt.
    pub async fn request_typed_with<R: CheckedControlRequest>(
        &self,
        request: &R,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ControlClientResult<R::Response> {
        let response = self
            .operation(
                request.json_request()?,
                configure(RequestOptions::default()),
            )
            .await?;
        request.decode_json(response)
    }

    /// Execute a generation-aware checked request using its historical JSON representation.
    pub async fn request_compatible<R: CompatibleControlRequest>(
        &self,
        request: &R,
        options: RequestOptions,
    ) -> ControlClientResult<R::Response> {
        let response = self
            .operation_bytes(request.compatibility_json_bytes()?, options)
            .await?;
        request.decode_compatibility_json(response)
    }

    pub(crate) async fn operation(
        &self,
        request: ControlRequest,
        options: RequestOptions,
    ) -> ControlClientResult<JsonReply> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&request).map_err(|_| ClientError::new(ErrorKind::Encode))?,
        );
        self.operation_bytes(bytes, options).await
    }

    pub(crate) async fn operation_bytes(
        &self,
        request: Zeroizing<Vec<u8>>,
        options: RequestOptions,
    ) -> ControlClientResult<JsonReply> {
        let until = deadline(
            options
                .request_timeout
                .or(self.options.limits.request_timeout)
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        )?;
        let setup_until = deadline(self.options.setup_timeout)?.min(until);
        if let Some(expected) = self.rediscover.filter(|_| !self.dialer.verified()) {
            // A path-only caller cannot reuse evidence about an old process.
            // Discover again before this new exchange; a format change closes
            // this handle instead of silently retargeting its prepared request.
            let mode = self
                .discover(setup_until)
                .await
                .map_err(crate::connection::not_sent);
            let mode = match mode {
                Ok((mode, _)) => mode,
                Err(error) => {
                    self.close().await;
                    return Err(error);
                }
            };
            if mode != expected {
                self.close().await;
                return Err(ControlClientError::RuntimeChanged);
            }
        }
        self.exchange_bytes(request, until, setup_until, None).await
    }

    pub(crate) async fn discover(
        &self,
        until: Instant,
    ) -> ControlClientResult<(ControlMode, crate::RuntimeCapabilities)> {
        let request = Zeroizing::new(
            serde_json::to_vec(&ControlRequest::Capabilities)
                .map_err(|_| ClientError::new(ErrorKind::Encode))?,
        );
        let reply = self
            .exchange_bytes(request, until, until, Some(MAX_DISCOVERY_RESPONSE_SIZE))
            .await?;
        let mode = reply.discovery_mode()?;
        let capabilities = crate::json_reply::capabilities(
            reply
                .value()
                .get("capabilities")
                .ok_or_else(|| ClientError::new(ErrorKind::InvalidData))?,
        )
        .ok_or_else(|| ClientError::new(ErrorKind::InvalidData))?;
        Ok((mode, capabilities))
    }

    async fn exchange_bytes(
        &self,
        mut line: Zeroizing<Vec<u8>>,
        until: Instant,
        setup_until: Instant,
        max_reply: Option<usize>,
    ) -> ControlClientResult<JsonReply> {
        line.push(b'\n');
        let mut admitted = false;
        let result = timeout_at(until, async {
            tokio::select! {
                biased;
                _ = self.closed.cancelled() => Err(ClientError::new(ErrorKind::Closed).into()),
                result = async {
                    check_deadline(setup_until)?;
                    let mut transport = timeout_at(setup_until, self.dialer.connect(setup_until)).await
                        .map_err(|_| ClientError::new(ErrorKind::Timeout))??;
                    check_deadline(setup_until)?;
                    timeout_at(setup_until, self.dialer.verify(setup_until)).await
                        .map_err(|_| ClientError::new(ErrorKind::Timeout))??;
                    check_deadline(until)?;
                    if self.closed.is_cancelled() { return Err(ClientError::new(ErrorKind::Closed).into()); }
                    // Mark uncertainty before the first write poll: even a
                    // partial failed write may have reached the peer.
                    admitted = true;
                    transport.write_all(&line).await.map_err(ClientError::from)?;
                    transport.flush().await.map_err(ClientError::from)?;
                    let mut reader = BufReader::new(transport);
                    let mut reply = Vec::new();
                    loop {
                        let buffer = reader.fill_buf().await.map_err(ClientError::from)?;
                        if buffer.is_empty() {
                            if reply.is_empty() { return Err(ClientError::new(ErrorKind::PeerClosed).into()); }
                            break;
                        }
                        let end = buffer.iter().position(|byte| *byte == b'\n').map(|index| index + 1);
                        let count = end.unwrap_or(buffer.len());
                        if max_reply.is_some_and(|limit| reply.len().saturating_add(count) > limit) {
                            return Err(ClientError::new(ErrorKind::InvalidData).into());
                        }
                        reply.extend_from_slice(&buffer[..count]);
                        reader.consume(count);
                        if end.is_some() { break; }
                    }
                    JsonReply::parse(reply)
                } => result,
            }
        }).await.unwrap_or_else(|_| Err(ClientError::new(ErrorKind::Timeout).into()));
        match result {
            Ok(reply) => Ok(reply),
            Err(error) => {
                self.closed.cancel();
                Err(match error {
                    ControlClientError::Client(error) => error
                        .with_delivery(if admitted {
                            Delivery::Unknown
                        } else {
                            Delivery::NotSent
                        })
                        .into(),
                    error => error,
                })
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn deadline(duration: Duration) -> ControlClientResult<Instant> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| ClientError::new(ErrorKind::InvalidOptions).into())
}

pub(crate) fn check_deadline(until: Instant) -> ControlClientResult<()> {
    if Instant::now() >= until {
        Err(ClientError::new(ErrorKind::Timeout).into())
    } else {
        Ok(())
    }
}
