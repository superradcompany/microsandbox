//! An agent connection held for one operation.
//!
//! Every operation owns its connection outright: nothing else uses it while the operation runs,
//! and dropping it unfinished closes it, which is how the guest learns to kill what the
//! operation started.
//!
//! A backend may keep connections open between operations. It then hands out an
//! [`AgentConnection`] that knows where it came from, and takes it back only if the operation
//! says it [finished](AgentConnection::finish). Anything else is closed as before.

use std::{
    ops::Deref,
    sync::{
        Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::time::Instant;

use super::AgentClient;
use crate::{MicrosandboxResult, backend::Backend};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Budget for obtaining a connection, matching the per-operation dial timeout.
const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One operation's exclusive hold on an agent connection.
///
/// Dereferences to the [`AgentClient`]. Share it between the parts of one operation with an
/// `Arc`; what happens to the connection is decided when the last of them lets go.
pub(crate) struct AgentConnection {
    /// The connection. Present until drop, which moves it out.
    client: Option<AgentClient>,

    /// Where a finished connection may go back to. Absent for a connection dialed for this
    /// operation alone.
    home: Option<Home>,

    /// Whether the operation ended and left nothing of itself on the connection.
    finished: AtomicBool,
}

/// Takes back connections whose operations finished.
///
/// Only the cloud backend keeps connections today, so without it nothing implements this.
#[cfg_attr(not(any(test, feature = "cloud")), allow(dead_code))]
pub(crate) trait Reclaim: Send + Sync {
    /// Offer a finished connection for reuse. The implementation keeps it or drops it.
    fn reclaim(&self, sandbox_id: &str, client: AgentClient, opened: Instant);
}

/// The pool a connection was taken from.
struct Home {
    /// Weak, so an outstanding connection never keeps its pool alive.
    pool: Weak<dyn Reclaim>,
    sandbox_id: String,
    opened: Instant,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentConnection {
    /// Wrap a connection dialed for this operation alone. It is always closed on drop.
    pub(crate) fn fresh(client: AgentClient) -> Self {
        Self {
            client: Some(client),
            home: None,
            finished: AtomicBool::new(false),
        }
    }

    /// Wrap a connection that `pool` will take back if the operation finishes.
    ///
    /// `opened` is when the connection was dialed, carried along so the pool can judge its age
    /// across uses.
    #[cfg_attr(not(any(test, feature = "cloud")), allow(dead_code))]
    pub(crate) fn pooled(
        client: AgentClient,
        opened: Instant,
        sandbox_id: &str,
        pool: Weak<dyn Reclaim>,
    ) -> Self {
        Self {
            client: Some(client),
            home: Some(Home {
                pool,
                sandbox_id: sandbox_id.to_owned(),
                opened,
            }),
            finished: AtomicBool::new(false),
        }
    }

    /// Whether a pool is waiting to take this connection back.
    pub(crate) fn is_pooled(&self) -> bool {
        self.home.is_some()
    }

    /// Record that the operation has ended and left nothing of itself on the connection.
    ///
    /// Call this only once the guest has reported the end: an exit, a refusal, or the single
    /// response to a single request. A connection never marked finished is closed on drop.
    pub(crate) fn finish(&self) {
        self.finished.store(true, Ordering::Release);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for AgentConnection {
    type Target = AgentClient;

    fn deref(&self) -> &Self::Target {
        self.client
            .as_ref()
            .expect("the connection is present until drop")
    }
}

impl Drop for AgentConnection {
    fn drop(&mut self) {
        let Some(client) = self.client.take() else {
            return;
        };
        let Some(home) = self.home.take() else {
            return;
        };

        // Unfinished means abandoned or failed. Closing is what tells the guest to clean up.
        if !self.finished.load(Ordering::Acquire) {
            return;
        }

        // A pool that is gone cannot take it; the connection closes instead.
        if let Some(pool) = home.pool.upgrade() {
            pool.reclaim(&home.sandbox_id, client, home.opened);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Obtain a connection for one operation against the named sandbox.
///
/// Returns one the backend kept open when it has one to offer, and a freshly dialed connection
/// otherwise. Either way the caller has it to itself.
pub(crate) async fn connect_for(
    backend: &dyn Backend,
    name: &str,
) -> MicrosandboxResult<AgentConnection> {
    #[cfg(feature = "cloud")]
    if let Some(cloud) = backend.as_cloud()
        && let Some(connection) = cloud.pooled_agent(name, AGENT_CONNECT_TIMEOUT).await?
    {
        return Ok(connection);
    }

    let client = backend.dial_agent(name, AGENT_CONNECT_TIMEOUT).await?;

    Ok(AgentConnection::fresh(client))
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
}
