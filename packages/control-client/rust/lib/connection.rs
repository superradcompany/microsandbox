//! Automatic format discovery outside the generic framed router.

use std::path::Path;
use std::sync::Arc;

use microsandbox_protocol::control::DEFAULT_REQUEST_TIMEOUT;
use microsandbox_protocol_client::{
    ClientError, ConnectOptions, Connector, Delivery, ErrorKind, LocalConnector, Message, Protocol,
    RequestOptions,
};
use tokio::time::timeout_at;
use tokio_util::sync::CancellationToken;

use crate::{
    CheckedControlRequest, ControlClient, ControlClientError, ControlClientResult, ControlProtocol,
    IntoControlMessage, JsonControlClient, JsonReply, VerifiedControlConnector,
    dialer::Dialer,
    json_client::{check_deadline, deadline},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Operation format selected during this connection's setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMode {
    /// Persistent, negotiated CBOR frames.
    Framed,
    /// Legacy JSON unary exchanges.
    Json,
}

/// The actual reply format. JSON never receives synthetic IDs or CBOR bytes.
#[derive(Debug)]
pub enum ControlReply {
    /// Original framed response, including unknown fields.
    Framed(Message),
    /// Original JSON line and its lossless inspection view.
    Json(JsonReply),
}

/// Shared discovery result and operation adapter. Standalone JSON connections
/// rediscover before fresh exchanges unless a verified runtime owner is supplied.
#[derive(Clone)]
pub struct ControlConnection {
    inner: Arc<Inner>,
}

struct Inner {
    selected: Selected,
    dialer: Dialer,
    options: ConnectOptions,
    closed: CancellationToken,
    capabilities: crate::Capabilities,
}

enum Selected {
    Framed(ControlClient),
    Json(JsonControlClient),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlConnection {
    /// Discover support at an existing native endpoint. Path identity alone is
    /// not sufficient to reuse JSON format evidence across process replacement.
    pub async fn connect(path: impl AsRef<Path>) -> ControlClientResult<Self> {
        Self::connect_with(path, |options| options).await
    }

    /// Configure one total deadline covering discovery, redial, and handshake.
    pub async fn connect_with(
        path: impl AsRef<Path>,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ControlClientResult<Self> {
        Self::connect_connector_with(Arc::new(LocalConnector::new(path)), configure).await
    }

    /// Discover using a repeatable, owned connector without claimed OS identity.
    pub async fn connect_connector(connector: Arc<dyn Connector>) -> ControlClientResult<Self> {
        Self::connect_connector_with(connector, |options| options).await
    }

    /// Configure discovery over caller-provided independent transports.
    pub async fn connect_connector_with(
        connector: Arc<dyn Connector>,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ControlClientResult<Self> {
        Self::establish(
            Dialer::Unverified(connector),
            configure(ConnectOptions::default()),
        )
        .await
    }

    /// Reuse JSON discovery while an external runtime owner verifies every peer
    /// and rechecks its active run and process birth before each operation.
    pub async fn connect_verified_connector(
        connector: Arc<dyn VerifiedControlConnector>,
    ) -> ControlClientResult<Self> {
        Self::connect_verified_connector_with(connector, |options| options).await
    }

    /// Configure setup for an identity-verifying backend connector.
    pub async fn connect_verified_connector_with(
        connector: Arc<dyn VerifiedControlConnector>,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ControlClientResult<Self> {
        Self::establish(
            Dialer::Verified(connector),
            configure(ConnectOptions::default()),
        )
        .await
    }

    async fn establish(dialer: Dialer, options: ConnectOptions) -> ControlClientResult<Self> {
        options.limits.validate()?;
        let until = deadline(options.setup_timeout)?;
        timeout_at(until, async {
            let json = JsonControlClient::configured(dialer.clone(), options.clone(), true);
            let (mode, capabilities) = json.discover(until).await?;
            let selected = match mode {
                ControlMode::Json => Selected::Json(json),
                ControlMode::Framed => {
                    // JSON completes on its own stream. A positively advertised
                    // framed path gets a fresh connection, never an in-place
                    // upgrade or a fallback after a failed welcome.
                    let transport = dialer.connect(until).await?;
                    dialer.verify(until).await?;
                    check_deadline(until)?;
                    let established =
                        ControlProtocol::establish(transport, options.clone()).await?;
                    Selected::Framed(ControlClient::from_established(established).await?)
                }
            };
            Ok(Self {
                inner: Arc::new(Inner {
                    selected,
                    dialer,
                    options,
                    closed: CancellationToken::new(),
                    capabilities,
                }),
            })
        })
        .await
        .unwrap_or_else(|_| Err(ClientError::new(ErrorKind::Timeout).into()))
        .map_err(not_sent)
    }

    /// Format selected by this setup. A later detected format change invalidates
    /// the JSON handle before sending; callers explicitly establish a new one.
    pub fn mode(&self) -> ControlMode {
        match self.inner.selected {
            Selected::Framed(_) => ControlMode::Framed,
            Selected::Json(_) => ControlMode::Json,
        }
    }

    /// Capability snapshot validated during discovery. Reading it performs no
    /// I/O; use GetCapabilities to explicitly request a fresh observation.
    pub fn capabilities(&self) -> &crate::Capabilities {
        &self.inner.capabilities
    }

    /// Inspect shared closure without dialing or rediscovery.
    pub fn is_closed(&self) -> bool {
        match &self.inner.selected {
            Selected::Framed(client) => client.is_closed(),
            Selected::Json(client) => client.is_closed(),
        }
    }

    /// Wait for the selected connection to close without dialing or polling.
    pub async fn closed(&self) {
        match &self.inner.selected {
            Selected::Framed(client) => client.closed().await,
            Selected::Json(client) => client.closed().await,
        }
    }

    /// Obtain the complete generic framed surface. JSON fails locally, without
    /// opening an endpoint or manufacturing an equivalent frame.
    pub fn framed(&self) -> ControlClientResult<&ControlClient> {
        match &self.inner.selected {
            Selected::Framed(client) => Ok(client),
            Selected::Json(_) => Err(ControlClientError::UnsupportedMode),
        }
    }

    /// Close all shared handles. Subsequent requests cannot silently reconnect.
    pub async fn close(&self) {
        // Verification can be awaiting a backend/database operation before the
        // generic client has a request to wake. It shares explicit close too.
        self.inner.closed.cancel();
        match &self.inner.selected {
            Selected::Framed(client) => client.close().await,
            Selected::Json(client) => client.close().await,
        }
    }

    /// Send a named request and retain its actual reply representation.
    pub async fn request(
        &self,
        message: impl IntoControlMessage,
    ) -> ControlClientResult<ControlReply> {
        self.request_with(message, |options| options).await
    }

    /// Configure one attempt, including any identity recheck or JSON rediscovery.
    pub async fn request_with(
        &self,
        message: impl IntoControlMessage,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ControlClientResult<ControlReply> {
        let options = configure(RequestOptions::default());
        match &self.inner.selected {
            Selected::Json(client) => Ok(ControlReply::Json(
                client.operation(message.into_json()?, options).await?,
            )),
            Selected::Framed(client) => {
                let options = self.verify_before_request(options).await?;
                Ok(ControlReply::Framed(
                    client.request_with(message, |_| options).await?,
                ))
            }
        }
    }

    /// Normalize a checked request using the selected format's real decoder.
    pub async fn request_typed<R: CheckedControlRequest>(
        &self,
        request: &R,
    ) -> ControlClientResult<R::Response> {
        self.request_typed_with(request, |options| options).await
    }

    /// Configure one checked operation's local wait.
    pub async fn request_typed_with<R: CheckedControlRequest>(
        &self,
        request: &R,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ControlClientResult<R::Response> {
        let options = configure(RequestOptions::default());
        match &self.inner.selected {
            Selected::Json(client) => {
                let reply = client.operation(request.json_request()?, options).await?;
                request.decode_json(reply)
            }
            Selected::Framed(client) => {
                let options = self.verify_before_request(options).await?;
                client.request_typed_with(request, |_| options).await
            }
        }
    }

    async fn verify_before_request(
        &self,
        options: RequestOptions,
    ) -> ControlClientResult<RequestOptions> {
        if self.is_closed() {
            return Err(ClientError::new(ErrorKind::Closed).into());
        }
        let until = deadline(
            options
                .request_timeout
                .or(self.inner.options.limits.request_timeout)
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT),
        )?;
        check_deadline(until)?;
        let result = tokio::select! {
            biased;
            _ = self.inner.closed.cancelled() => Err(ClientError::new(ErrorKind::Closed).into()),
            result = timeout_at(until, self.inner.dialer.verify(until)) => result
                .unwrap_or_else(|_| Err(ClientError::new(ErrorKind::Timeout).into())),
        };
        if let Err(error) = result {
            self.close().await;
            return Err(not_sent(error));
        }
        check_deadline(until)?;
        Ok(RequestOptions::default()
            .request_timeout(until.saturating_duration_since(tokio::time::Instant::now())))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn not_sent(error: ControlClientError) -> ControlClientError {
    match error {
        ControlClientError::Client(error) => error.with_delivery(Delivery::NotSent).into(),
        error => error,
    }
}
