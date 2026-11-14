//! Fixture decoding, isolated backend construction, and synchronization for crate unit tests.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use microsandbox_protocol::{
    codec,
    core::Ready,
    message::{Message, MessageType},
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    time::Instant,
};

use crate::agent::{AgentClient, AgentConnection, Reclaim};

pub(crate) mod fixtures;
mod json;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Virtio-fs backend state budget of a default configuration, in bytes.
pub(crate) const DEFAULT_FS_STATE_LIMIT: usize = 4 * 1024 * 1024;

/// Serializes process-global environment mutation across SDK unit tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stands in for a backend's connection pool and records what is handed back to it.
#[derive(Default)]
pub(crate) struct ReclaimedAgents(Mutex<Vec<AgentClient>>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ReclaimedAgents {
    /// How many connections have come back so far.
    pub(crate) fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Reclaim for ReclaimedAgents {
    fn reclaim(&self, _sandbox_id: &str, client: AgentClient, _opened: Instant) {
        // Holding the client keeps the connection open, as a real pool would.
        self.0.lock().unwrap().push(client);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Lock process-global environment mutation for the duration of a unit test.
pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// Construct a cloud backend with explicitly empty config sources, independent of the host.
#[cfg(feature = "cloud")]
pub(crate) fn cloud_backend(
    url: impl Into<String>,
    api_key: impl Into<String>,
) -> crate::MicrosandboxResult<crate::CloudBackend> {
    crate::CloudBackend::builder()
        .url(url)
        .api_key(api_key)
        .config_sources(crate::config::layers::BackendConfig::new(
            Default::default(),
            Default::default(),
        ))
        .agent_reuse(false)
        .build()
}

/// Construct a cloud backend like [`cloud_backend`], with agent connection reuse switched on the
/// way the environment flag switches it.
#[cfg(feature = "cloud")]
pub(crate) fn cloud_backend_reusing_agents(
    url: impl Into<String>,
    api_key: impl Into<String>,
) -> crate::MicrosandboxResult<crate::CloudBackend> {
    crate::CloudBackend::builder()
        .url(url)
        .api_key(api_key)
        .config_sources(crate::config::layers::BackendConfig::new(
            Default::default(),
            Default::default(),
        ))
        .agent_reuse(true)
        .build()
}

/// Connect an agent client to an in-memory peer that has already sent the relay handshake.
///
/// The peer reads and writes the frames a relay would, so a test can play the guest.
pub(crate) async fn agent_client_pair() -> (AgentClient, DuplexStream) {
    let (host, mut peer) = tokio::io::duplex(64 * 1024);
    let connect = AgentClient::connect_stream_with_timeout(host, Duration::from_secs(3));
    let handshake = async {
        peer.write_all(&1u32.to_be_bytes()).await.unwrap();
        peer.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let ready = Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
        codec::write_message(&mut peer, &ready).await.unwrap();

        peer
    };
    let (client, peer) = tokio::join!(connect, handshake);

    (client.unwrap(), peer)
}

/// Connect an in-memory agent connection that goes back to a recording pool if it finishes.
pub(crate) async fn pooled_agent_connection()
-> (AgentConnection, DuplexStream, Arc<ReclaimedAgents>) {
    let (client, peer) = agent_client_pair().await;
    let pool = Arc::new(ReclaimedAgents::default());
    let home = Arc::downgrade(&pool);
    let connection = AgentConnection::pooled(client, Instant::now(), "sandbox", home);

    (connection, peer, pool)
}

/// Wait for the far end of an agent connection to see it close, skipping frames still in flight.
pub(crate) async fn expect_closed(peer: &mut DuplexStream) {
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        while codec::read_message(&mut *peer).await.is_ok() {}
    })
    .await;

    assert!(closed.is_ok(), "the connection was expected to close");
}

/// Assert that the far end of an agent connection receives nothing and stays open.
pub(crate) async fn expect_silence(peer: &mut DuplexStream) {
    let frame = tokio::time::timeout(Duration::from_millis(100), codec::read_message(peer)).await;

    assert!(frame.is_err(), "no frame and no close were expected");
}

/// Construct a local backend from explicit settings without reading machine configuration.
#[cfg(feature = "local")]
pub(crate) fn local_backend(config: crate::config::GlobalConfig) -> crate::LocalBackend {
    crate::LocalBackend::from_backend_config(
        crate::config::layers::BackendConfig::new(
            crate::config::GlobalConfigPatch::from_present_fields(config),
            Default::default(),
        ),
        crate::BackendSelectionSource::Programmatic,
        None,
    )
}

/// Build against user and managed config files inside a test's temporary home.
/// Runtime environment paths are still honored for live runtime fixtures.
#[cfg(feature = "local")]
pub(crate) fn local_backend_builder(
    home: impl AsRef<std::path::Path>,
) -> crate::backend::local::LocalBackendBuilder {
    let home = home.as_ref();
    crate::LocalBackend::builder()
        .config_path(home.join("config.json"))
        .managed_config_path(home.join("managed.json"))
        .home(home)
}
