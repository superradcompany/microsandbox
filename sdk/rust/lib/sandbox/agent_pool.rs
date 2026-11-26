//! Per-run pool of idle cloud agent WebSocket connections.
//!
//! Connections are exclusive while an operation runs. Finished connections return here for reuse
//! on the same sandbox run; abandoned or failed connections close so the guest cleans up.

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use tokio::{runtime::Handle, task::AbortHandle, time::Instant};

use crate::{
    MicrosandboxResult,
    agent::{AgentClient, AgentConnection},
    timing,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum idle connections kept per sandbox run (relay slots are shared across processes).
const MAX_IDLE_CONNECTIONS: usize = 2;

/// Longest a connection may sit unused before a timer closes it (half of common proxy idle limits).
const MAX_IDLE: Duration = Duration::from_secs(30);

/// Maximum lifetime of a pooled connection so revoked API keys stop being reused promptly.
const MAX_AGE: Duration = Duration::from_secs(5 * 60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Idle agent connections for a single cloud sandbox run.
pub(crate) struct AgentPool {
    /// Most recently used last, so the freshest connection is reused first and older ones expire.
    idle: Mutex<Vec<IdleAgent>>,
}

struct IdleAgent {
    client: AgentClient,
    opened: Instant,
    idle_since: Instant,
    /// Wall clock timestamp so time spent with the machine asleep counts toward idle expiry.
    idle_since_wall: SystemTime,
    _timer: IdleTimer,
}

/// Closes an idle connection when its deadline passes without waiting for another checkout.
struct IdleTimer(Option<AbortHandle>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentPool {
    pub(crate) fn new() -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Take an idle connection if a valid one is available, or dial a fresh one.
    pub(crate) async fn checkout<F, Fut>(
        self: &Arc<Self>,
        dial: F,
    ) -> MicrosandboxResult<AgentConnection>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = MicrosandboxResult<AgentClient>>,
    {
        if let Some(entry) = self.take_idle() {
            tracing::trace!(target: timing::TARGET, reused = true, "cloud agent connection selected");
            return Ok(self.wrap(entry.client, entry.opened));
        }

        let client = dial().await?;
        tracing::trace!(target: timing::TARGET, reused = false, "cloud agent connection selected");
        Ok(self.wrap(client, Instant::now()))
    }

    /// Close and discard every idle connection in this pool.
    pub(crate) fn evict(&self) {
        let evicted = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *idle)
        };
        drop(evicted);
    }

    fn wrap(self: &Arc<Self>, client: AgentClient, opened: Instant) -> AgentConnection {
        let pool = Arc::downgrade(self);
        AgentConnection::pooled(client, move |client| {
            if let Some(pool) = pool.upgrade() {
                pool.release(client, opened);
            }
        })
    }

    fn release(self: &Arc<Self>, client: AgentClient, opened: Instant) {
        if client.is_closed() || client.is_exhausted() {
            return;
        }

        let now = Instant::now();
        let wall_now = SystemTime::now();
        let mut closed = Vec::new();
        let rejected = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            prune_expired(&mut idle, now, wall_now, &mut closed);

            let age = now.duration_since(opened);
            if age < MAX_AGE && idle.len() < MAX_IDLE_CONNECTIONS {
                let remaining_age = MAX_AGE.saturating_sub(age);
                let timeout = MAX_IDLE.min(remaining_age);
                idle.push(IdleAgent {
                    client,
                    opened,
                    idle_since: now,
                    idle_since_wall: wall_now,
                    _timer: IdleTimer::start(self, timeout),
                });
                None
            } else {
                Some(client)
            }
        };

        // Close sockets outside the mutex lock.
        drop(closed);
        drop(rejected);
    }

    fn take_idle(&self) -> Option<IdleAgent> {
        let mut closed = Vec::new();
        let taken = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            prune_expired(&mut idle, Instant::now(), SystemTime::now(), &mut closed);
            idle.pop()
        };

        drop(closed);
        taken
    }

    fn close_expired(&self) {
        let mut closed = Vec::new();
        {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            prune_expired(&mut idle, Instant::now(), SystemTime::now(), &mut closed);
        }

        drop(closed);
    }
}

impl IdleAgent {
    fn idle_for(&self, now: Instant, wall_now: SystemTime) -> Duration {
        let monotonic = now.duration_since(self.idle_since);
        let wall = wall_now
            .duration_since(self.idle_since_wall)
            .unwrap_or_default();
        monotonic.max(wall)
    }

    fn is_usable(&self, now: Instant, wall_now: SystemTime) -> bool {
        !self.client.is_closed()
            && !self.client.is_exhausted()
            && now.duration_since(self.opened) < MAX_AGE
            && self.idle_for(now, wall_now) < MAX_IDLE
    }
}

impl IdleTimer {
    fn start(pool: &Arc<AgentPool>, after: Duration) -> Self {
        let Ok(runtime) = Handle::try_current() else {
            return Self(None);
        };
        let pool = Arc::downgrade(pool);
        let timer = runtime.spawn(async move {
            tokio::time::sleep(after).await;
            if let Some(pool) = pool.upgrade() {
                pool.close_expired();
            }
        });
        Self(Some(timer.abort_handle()))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for IdleTimer {
    fn drop(&mut self) {
        if let Some(timer) = self.0.take() {
            timer.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn prune_expired(
    idle: &mut Vec<IdleAgent>,
    now: Instant,
    wall_now: SystemTime,
    closed: &mut Vec<IdleAgent>,
) {
    let mut index = 0;
    while index < idle.len() {
        if idle[index].is_usable(now, wall_now) {
            index += 1;
        } else {
            closed.push(idle.remove(index));
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_protocol::{
        codec,
        core::Ready,
        exec::ExecSignal,
        fs::{FsOp, FsRequest, FsResponse},
        message::{Message, MessageType},
    };
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::*;
    use crate::{MicrosandboxError, test_support};

    #[derive(Default)]
    struct Dialer {
        far_ends: tokio::sync::Mutex<Vec<Option<DuplexStream>>>,
    }

    impl Dialer {
        async fn dial(&self) -> MicrosandboxResult<AgentClient> {
            let (client, far_end) = test_support::agent_client_pair().await;
            self.far_ends.lock().await.push(Some(far_end));
            Ok(client)
        }

        async fn dials(&self) -> usize {
            self.far_ends.lock().await.len()
        }

        async fn hears(&self, dial: usize, connection: &AgentConnection) -> bool {
            let marker = ExecSignal { signal: 15 };
            connection
                .send(1, MessageType::ExecSignal, &marker)
                .await
                .unwrap();

            let mut far_ends = self.far_ends.lock().await;
            let far_end = far_ends[dial].as_mut().expect("the far end is still up");
            let frame =
                tokio::time::timeout(Duration::from_millis(500), codec::read_message(far_end))
                    .await;

            frame.is_ok_and(|frame| frame.is_ok())
        }

        async fn expect_closed(&self, dial: usize) {
            let mut far_ends = self.far_ends.lock().await;
            let far_end = far_ends[dial].as_mut().expect("the far end is still up");
            test_support::expect_closed(far_end).await;
        }

        async fn hang_up(&self, dial: usize) {
            self.far_ends.lock().await[dial] = None;
        }
    }

    #[tokio::test]
    async fn finished_connection_serves_the_next_operation() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        first.finish();
        drop(first);
        let second = pool.checkout(|| dialer.dial()).await.unwrap();

        assert_eq!(dialer.dials().await, 1);
        assert!(dialer.hears(0, &second).await);
    }

    #[tokio::test]
    async fn abandoned_connection_is_closed_rather_than_kept() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        drop(first);
        let _second = pool.checkout(|| dialer.dial()).await.unwrap();

        assert_eq!(dialer.dials().await, 2);
        dialer.expect_closed(0).await;
    }

    #[tokio::test]
    async fn concurrent_operations_each_get_a_connection_and_up_to_two_wait() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        let second = pool.checkout(|| dialer.dial()).await.unwrap();
        let third = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 3);

        first.finish();
        drop(first);
        second.finish();
        drop(second);
        third.finish();
        drop(third);

        // Only MAX_IDLE_CONNECTIONS (2) are kept; the third closes immediately.
        dialer.expect_closed(2).await;

        let fourth = pool.checkout(|| dialer.dial()).await.unwrap();
        let fifth = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 3);
        assert!(dialer.hears(1, &fourth).await);
        assert!(dialer.hears(0, &fifth).await);
    }

    #[tokio::test]
    async fn evict_closes_all_idle_connections() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        let second = pool.checkout(|| dialer.dial()).await.unwrap();
        first.finish();
        second.finish();
        drop((first, second));

        pool.evict();
        dialer.expect_closed(0).await;
        dialer.expect_closed(1).await;

        let _next = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_closed_at_idle_limit_without_another_checkout() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let only = pool.checkout(|| dialer.dial()).await.unwrap();
        only.finish();
        drop(only);

        tokio::time::sleep(MAX_IDLE - Duration::from_secs(1)).await;
        assert_eq!(pool.idle.lock().unwrap().len(), 1);

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(pool.idle.lock().unwrap().is_empty());
        dialer.expect_closed(0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_closed_at_max_age_without_another_checkout() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let only = pool.checkout(|| dialer.dial()).await.unwrap();
        tokio::time::advance(MAX_AGE - Duration::from_secs(5)).await;
        only.finish();
        drop(only);

        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(pool.idle.lock().unwrap().len(), 1);

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(pool.idle.lock().unwrap().is_empty());
        dialer.expect_closed(0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn connection_that_waits_again_gets_its_full_idle_time_again() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        first.finish();
        drop(first);
        tokio::time::sleep(Duration::from_secs(20)).await;
        let second = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 1);
        second.finish();
        drop(second);

        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(pool.idle.lock().unwrap().len(), 1);

        tokio::time::sleep(Duration::from_secs(16)).await;
        assert!(pool.idle.lock().unwrap().is_empty());
        dialer.expect_closed(0).await;
    }

    #[tokio::test]
    async fn connection_handed_back_outside_a_runtime_waits_without_a_timer() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        first.finish();
        std::thread::spawn(move || drop(first)).join().unwrap();
        let _second = pool.checkout(|| dialer.dial()).await.unwrap();

        assert_eq!(dialer.dials().await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn age_counts_from_dial_across_uses() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        tokio::time::advance(Duration::from_secs(180)).await;
        first.finish();
        drop(first);
        let second = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 1);
        tokio::time::advance(Duration::from_secs(180)).await;
        second.finish();
        drop(second);

        // Total age is 360s > MAX_AGE (300s), so it is closed on release.
        dialer.expect_closed(0).await;
        let _third = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 2);
    }

    #[tokio::test]
    async fn closed_idle_connection_is_skipped_and_redialed() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout(|| dialer.dial()).await.unwrap();
        first.finish();
        drop(first);
        dialer.hang_up(0).await;
        tokio::task::yield_now().await;

        let second = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 2);
        assert!(dialer.hears(1, &second).await);
    }

    #[tokio::test]
    async fn dial_failure_propagates_without_poisoning_pool() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let error = pool
            .checkout(|| async { Err(MicrosandboxError::Runtime("unreachable".into())) })
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unreachable"));

        let ok = pool.checkout(|| dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 1);
        assert!(dialer.hears(0, &ok).await);
    }

    #[tokio::test]
    async fn exhausted_correlation_ids_prevent_reuse() {
        let (host, mut peer) = tokio::io::duplex(64 * 1024);
        let connect = AgentClient::connect_stream_with_timeout(host, Duration::from_secs(3));
        let handshake = async {
            // Range [1, 2) provides a single correlation ID.
            peer.write_all(&1u32.to_be_bytes()).await.unwrap();
            peer.write_all(&2u32.to_be_bytes()).await.unwrap();
            let ready = Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
            codec::write_message(&mut peer, &ready).await.unwrap();
        };
        let (client, ()) = tokio::join!(connect, handshake);
        let client = client.unwrap();

        let pool = Arc::new(AgentPool::new());
        let connection = pool.checkout(|| async { Ok(client) }).await.unwrap();
        let request = FsRequest {
            op: FsOp::Mkdir {
                path: "/x".into(),
                mode: None,
                user: None,
            },
            bulk: None,
        };
        let reply = async {
            let msg = codec::read_message(&mut peer).await.unwrap();
            let resp = Message::with_payload(
                MessageType::FsResponse,
                msg.id,
                &FsResponse {
                    ok: true,
                    error: None,
                    data: None,
                },
            )
            .unwrap();
            codec::write_message(&mut peer, &resp).await.unwrap();
        };
        let (res, ()) = tokio::join!(
            connection.request_once(MessageType::FsRequest, &request),
            reply
        );
        res.unwrap();
        drop(connection);

        // Exhausted client was rejected on release and closed.
        test_support::expect_closed(&mut peer).await;
        assert!(pool.idle.lock().unwrap().is_empty());
    }
}
