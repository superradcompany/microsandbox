//! An agent connection held for one operation.
//!
//! Exclusive connections are owned by one operation at a time; dropping an unfinished connection
//! closes it so the guest cleans up. A pooled connection returns to its pool when marked
//! [finished](AgentConnection::finish). Shared connections (local runs and SSH) release only
//! their `Arc` reference on drop.

use std::{
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use microsandbox_protocol::message::{Message, MessageType};
use serde::Serialize;

use super::AgentClient;
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default budget for dialing a sandbox agent connection.
pub(crate) const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type ReleaseFn = Box<dyn FnOnce(AgentClient) + Send + Sync>;

/// One operation's hold on an agent connection.
///
/// Dereferences to [`AgentClient`]. Share across tasks of one operation with an `Arc`; release
/// happens when the last reference drops.
pub(crate) struct AgentConnection {
    client: ConnectionClient,
    on_release: Option<ReleaseFn>,
    finished: AtomicBool,
}

enum ConnectionClient {
    Exclusive(Option<Box<AgentClient>>),
    Shared(Arc<AgentClient>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentConnection {
    /// Wrap a connection dialed for this operation alone; always closed on drop.
    pub(crate) fn fresh(client: AgentClient) -> Self {
        Self {
            client: ConnectionClient::Exclusive(Some(Box::new(client))),
            on_release: None,
            finished: AtomicBool::new(false),
        }
    }

    /// Wrap a connection shared by a local sandbox run or SSH session.
    pub(crate) fn shared(client: Arc<AgentClient>) -> Self {
        Self {
            client: ConnectionClient::Shared(client),
            on_release: None,
            finished: AtomicBool::new(false),
        }
    }

    /// Wrap a connection that calls `on_release` on drop if the operation [finished](Self::finish).
    #[cfg(any(test, feature = "cloud"))]
    pub(crate) fn pooled(
        client: AgentClient,
        on_release: impl FnOnce(AgentClient) + Send + Sync + 'static,
    ) -> Self {
        Self {
            client: ConnectionClient::Exclusive(Some(Box::new(client))),
            on_release: Some(Box::new(on_release)),
            finished: AtomicBool::new(false),
        }
    }

    /// Mark that the operation ended cleanly so a pooled connection can be reused.
    pub(crate) fn finish(&self) {
        self.finished.store(true, Ordering::Release);
    }

    /// Send a single request, mark the connection finished on reply, and return the response.
    pub(crate) async fn request_once<T: Serialize>(
        &self,
        msg_type: MessageType,
        payload: &T,
    ) -> MicrosandboxResult<Message> {
        let response = self.request(msg_type, payload).await?;
        self.finish();
        Ok(response)
    }

    /// Consume this hold into a shared `Arc<AgentClient>` for long-lived streams or handles.
    ///
    /// Exclusive connections are detached from any pool callback and close when the last `Arc`
    /// drops.
    pub(crate) fn into_client(mut self) -> Arc<AgentClient> {
        self.on_release = None;
        match &mut self.client {
            ConnectionClient::Exclusive(slot) => {
                Arc::new(*slot.take().expect("the connection is present until drop"))
            }
            ConnectionClient::Shared(client) => Arc::clone(client),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for AgentConnection {
    type Target = AgentClient;

    fn deref(&self) -> &Self::Target {
        match &self.client {
            ConnectionClient::Exclusive(client) => client
                .as_deref()
                .expect("the connection is present until drop"),
            ConnectionClient::Shared(client) => client.as_ref(),
        }
    }
}

impl Drop for AgentConnection {
    fn drop(&mut self) {
        let ConnectionClient::Exclusive(slot) = &mut self.client else {
            return;
        };
        let Some(client) = slot.take() else {
            return;
        };
        let Some(on_release) = self.on_release.take() else {
            return;
        };

        // Unfinished means abandoned or failed; closing tells the guest to clean up.
        if !self.finished.load(Ordering::Acquire) {
            return;
        }

        on_release(*client);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{
        agent_client_pair, expect_closed, expect_silence, pooled_agent_connection,
    };

    #[tokio::test]
    async fn finished_connection_goes_back_to_its_pool() {
        let (connection, mut peer, pool) = pooled_agent_connection().await;

        connection.finish();
        drop(connection);

        assert_eq!(pool.count(), 1);
        expect_silence(&mut peer).await;
    }

    #[tokio::test]
    async fn unfinished_connection_is_closed() {
        let (connection, mut peer, pool) = pooled_agent_connection().await;

        drop(connection);

        assert_eq!(pool.count(), 0);
        expect_closed(&mut peer).await;
    }

    #[tokio::test]
    async fn finished_connection_is_closed_when_its_pool_is_gone() {
        let (connection, mut peer, pool) = pooled_agent_connection().await;

        connection.finish();
        drop(pool);
        drop(connection);

        expect_closed(&mut peer).await;
    }

    #[tokio::test]
    async fn fresh_connection_is_closed_even_when_finished() {
        let (client, mut peer) = agent_client_pair().await;
        let connection = AgentConnection::fresh(client);

        connection.finish();
        drop(connection);

        expect_closed(&mut peer).await;
    }

    #[tokio::test]
    async fn shared_connection_stays_open_while_another_owner_holds_the_client() {
        let (client, mut peer) = agent_client_pair().await;
        let shared = Arc::new(client);
        let connection = AgentConnection::shared(Arc::clone(&shared));

        drop(connection);

        expect_silence(&mut peer).await;
        drop(shared);
        expect_closed(&mut peer).await;
    }

    #[tokio::test]
    async fn last_owner_settles_what_happens_to_the_connection() {
        let (connection, mut peer, pool) = pooled_agent_connection().await;
        let first = Arc::new(connection);
        let second = Arc::clone(&first);

        first.finish();
        drop(first);
        assert_eq!(pool.count(), 0, "another owner still holds the connection");
        expect_silence(&mut peer).await;
        drop(second);

        assert_eq!(pool.count(), 1);
    }

    #[tokio::test]
    async fn into_client_detaches_pooled_connection_from_pool() {
        let (connection, mut peer, pool) = pooled_agent_connection().await;
        let client = connection.into_client();

        assert_eq!(pool.count(), 0);
        expect_silence(&mut peer).await;
        drop(client);

        assert_eq!(pool.count(), 0);
        expect_closed(&mut peer).await;
    }
}
