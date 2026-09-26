//! Configured client entry points that preserve one total setup deadline.

use std::ops::Deref;
use std::path::Path;

use microsandbox_protocol::supervisor::{
    ClientInstanceId, DEFAULT_SUPERVISOR_MAX_IN_FLIGHT, DEFAULT_SUPERVISOR_MAX_WATCHES,
    DEFAULT_SUPERVISOR_SETUP_TIMEOUT, HomeDigest, MIN_SUPERVISOR_GENERATION, SUPERVISOR_GENERATION,
    SUPERVISOR_PROTOCOL, SupervisorHello, SupervisorLimits,
};
use microsandbox_protocol_client::{
    BoxTransport, ByteTransport, Client, ClientError, ClientResult, ConnectOptions, Connector,
    ErrorKind, LocalConnector,
};
use tokio::time::Instant;

use crate::SupervisorProtocol;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Identity and home binding required by the supervisor handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorClientConfig {
    /// Client package or SDK version for diagnostics.
    pub implementation_version: String,
    /// Per-process diagnostic identity.
    pub client_instance_id: ClientInstanceId,
    /// Digest of the canonical microsandbox home targeted by the endpoint.
    pub canonical_home_digest: HomeDigest,
    /// Last catalog revision already consumed after reconnect, when any.
    pub resume_catalog_revision: Option<u64>,
    /// Maximum watch streams this caller will open.
    pub max_watches: u32,
}

/// Configured supervisor connection backed by the shared framed router.
pub struct SupervisorClient {
    inner: Client<SupervisorProtocol>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorClientConfig {
    /// Bind a client process identity to one canonical microsandbox home.
    pub fn new(client_instance_id: ClientInstanceId, canonical_home_digest: HomeDigest) -> Self {
        Self {
            implementation_version: env!("CARGO_PKG_VERSION").into(),
            client_instance_id,
            canonical_home_digest,
            resume_catalog_revision: None,
            max_watches: DEFAULT_SUPERVISOR_MAX_WATCHES,
        }
    }

    /// Override the diagnostic implementation version reported during setup.
    pub fn implementation_version(mut self, version: impl Into<String>) -> Self {
        self.implementation_version = version.into();
        self
    }

    /// Resume catalog consumption after the supplied committed revision.
    pub fn resume_catalog_revision(mut self, revision: u64) -> Self {
        self.resume_catalog_revision = Some(revision);
        self
    }

    /// Request a caller-specific watch-stream ceiling.
    pub fn max_watches(mut self, maximum: u32) -> Self {
        self.max_watches = maximum;
        self
    }
}

impl SupervisorClient {
    /// Connect a Unix socket or Windows named pipe using default transport options.
    pub async fn connect(
        path: impl AsRef<Path>,
        config: SupervisorClientConfig,
    ) -> ClientResult<Self> {
        Self::connect_with(path, config, |options| options).await
    }

    /// Configure transport resource limits while retaining the explicit handshake identity.
    pub async fn connect_with(
        path: impl AsRef<Path>,
        config: SupervisorClientConfig,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ClientResult<Self> {
        Self::connect_connector_with(&LocalConnector::new(path), config, configure).await
    }

    /// Connect through a repeatable caller-provided dialer.
    pub async fn connect_connector(
        connector: &dyn Connector,
        config: SupervisorClientConfig,
    ) -> ClientResult<Self> {
        Self::connect_connector_with(connector, config, |options| options).await
    }

    /// Configure one deadline covering dial, MSBS selection, and framed setup.
    pub async fn connect_connector_with(
        connector: &dyn Connector,
        config: SupervisorClientConfig,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ClientResult<Self> {
        let options = configured_options(config.max_watches, configure(supervisor_options()))?;
        let deadline = deadline(options.setup_timeout)?;
        tokio::time::timeout_at(deadline, async {
            let stream = connector.connect(deadline).await?;
            Self::establish(stream, options, config).await
        })
        .await
        .map_err(|_| ClientError::new(ErrorKind::Timeout))?
    }

    /// Establish on a caller-owned byte transport.
    pub async fn connect_stream(
        stream: impl ByteTransport,
        config: SupervisorClientConfig,
    ) -> ClientResult<Self> {
        Self::connect_stream_with(stream, config, |options| options).await
    }

    /// Configure setup for a caller-owned byte transport.
    pub async fn connect_stream_with(
        stream: impl ByteTransport,
        config: SupervisorClientConfig,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ClientResult<Self> {
        let options = configured_options(config.max_watches, configure(supervisor_options()))?;
        let deadline = deadline(options.setup_timeout)?;
        tokio::time::timeout_at(deadline, Self::establish(Box::new(stream), options, config))
            .await
            .map_err(|_| ClientError::new(ErrorKind::Timeout))?
    }

    async fn establish(
        stream: BoxTransport,
        options: ConnectOptions,
        config: SupervisorClientConfig,
    ) -> ClientResult<Self> {
        let hello = SupervisorHello {
            protocol: SUPERVISOR_PROTOCOL.into(),
            min_generation: MIN_SUPERVISOR_GENERATION,
            max_generation: SUPERVISOR_GENERATION,
            implementation_version: config.implementation_version,
            client_instance_id: config.client_instance_id,
            canonical_home_digest: config.canonical_home_digest,
            requested_limits: SupervisorLimits {
                max_frame_size: options.limits.max_frame_size,
                max_in_flight: options
                    .limits
                    .max_in_flight
                    .min(DEFAULT_SUPERVISOR_MAX_IN_FLIGHT as usize)
                    as u32,
                max_watches: config.max_watches,
            },
            resume_catalog_revision: config.resume_catalog_revision,
        };
        let established = SupervisorProtocol::establish_configured(stream, options, hello).await?;
        Ok(Self {
            inner: Client::from_established(established).await?,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for SupervisorClient {
    type Target = Client<SupervisorProtocol>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Clone for SupervisorClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn configured_options(
    max_watches: u32,
    mut options: ConnectOptions,
) -> ClientResult<ConnectOptions> {
    options.limits.max_frame_size = options
        .limits
        .max_frame_size
        .min(microsandbox_protocol::supervisor::MAX_SUPERVISOR_FRAME_SIZE);
    options.limits.max_in_flight = options
        .limits
        .max_in_flight
        .min(DEFAULT_SUPERVISOR_MAX_IN_FLIGHT as usize);
    if max_watches == 0 || max_watches > options.limits.max_in_flight as u32 {
        return Err(ClientError::new(ErrorKind::InvalidOptions));
    }
    options.limits.validate()?;
    Ok(options)
}

fn supervisor_options() -> ConnectOptions {
    ConnectOptions {
        setup_timeout: DEFAULT_SUPERVISOR_SETUP_TIMEOUT,
        limits: microsandbox_protocol_client::ClientLimits {
            max_frame_size: microsandbox_protocol::supervisor::DEFAULT_SUPERVISOR_FRAME_SIZE,
            max_in_flight: DEFAULT_SUPERVISOR_MAX_IN_FLIGHT as usize,
            ..Default::default()
        },
    }
}

fn deadline(timeout: std::time::Duration) -> ClientResult<Instant> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ClientError::new(ErrorKind::InvalidOptions))?;
    if deadline <= Instant::now() {
        return Err(ClientError::new(ErrorKind::Timeout));
    }
    Ok(deadline)
}
