//! Experimental: keep cloud agent connections open between operations.
//!
//! By default every agent operation opens its own WebSocket and closes it afterwards. Opening
//! one costs a handshake with the edge and, far more, the upgrade through to the sandbox. When
//! `MSB_CLOUD_AGENT_REUSE` is set, a connection whose operation finished is kept for the next
//! operation on the same sandbox.
//!
//! Connections are never shared. An operation takes one out of the pool, has it to itself, and
//! gives it back only by finishing. An abandoned or failed operation's connection is closed, so
//! the guest cleans up exactly as it does without the pool.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use tokio::{runtime::Handle, task::AbortHandle, time::Instant};

use crate::{
    MicrosandboxResult,
    agent::{AgentClient, AgentConnection, Reclaim},
    timing,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Environment variable that turns connection reuse on (`1` or `true`).
pub(super) const AGENT_REUSE_ENV: &str = "MSB_CLOUD_AGENT_REUSE";

/// Most connections that may wait for one sandbox.
///
/// A caller that runs one operation at a time only ever fills one place. The second is for a
/// caller with two things going at once, so that neither of them dials every time. Each waiting
/// connection holds one of the sandbox's 128 relay slots, which other SDK processes and the CLI
/// draw on too, so the number stays small.
const MAX_WAITING: usize = 2;

/// Longest a connection may wait unused. A timer closes it when the time is up, whether or not
/// another operation ever asks for one.
///
/// Nothing probes a waiting connection. One that the far end closed is noticed and skipped, but
/// one that the network dropped without notice is only found by the operation that gets it,
/// which then hangs until its own timeout. Common proxy defaults close an idle WebSocket after
/// about a minute, and half of that stays clear of racing one.
const MAX_IDLE: Duration = Duration::from_secs(30);

/// Oldest a connection may be and still be given to another operation.
///
/// The API key is checked only when a connection opens, so this is how long a revoked key can go
/// on starting operations. Replacing a connection this often costs one extra dial each time.
const MAX_AGE: Duration = Duration::from_secs(5 * 60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What the pool knows about a connection when it decides whether to keep it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Candidate {
    /// How long ago the connection was opened.
    pub(crate) age: Duration,

    /// How long it has sat unused, including time the machine spent asleep. Zero for a
    /// connection whose operation has just finished.
    pub(crate) idle_for: Duration,

    /// How many other connections this sandbox already has waiting.
    pub(crate) idle_peers: usize,
}

/// Decides whether a connection stays in the pool.
pub(crate) type Policy = fn(&Candidate) -> bool;

/// Waiting agent connections for one backend, grouped by sandbox ID.
pub(crate) struct AgentPool {
    /// Most recently used last, so the freshest connection is handed out first and the rest
    /// are left to age out.
    waiting: Mutex<HashMap<String, Vec<WaitingAgent>>>,

    policy: Policy,
}

/// The outcome of asking the pool for a connection.
pub(super) struct Checkout {
    /// The connection, for this operation alone.
    pub(super) connection: AgentConnection,

    /// Whether it was waiting in the pool, as opposed to dialed by this checkout.
    pub(super) reused: bool,
}

/// A connection between operations.
struct WaitingAgent {
    client: AgentClient,
    opened: Instant,
    waiting_since: Instant,

    /// The same moment on the wall clock, which keeps going while the machine sleeps.
    waiting_since_wall: SystemTime,

    /// Closes the connection once it has waited too long. Held only to be dropped.
    _expiry: Expiry,
}

/// The timer of one waiting connection.
///
/// Without it a connection would only be let go when a later operation looked for one. A
/// caller that went quiet would keep its connections, and the relay slots they hold, for as
/// long as the backend lived. Dropping this stops the timer.
struct Expiry(Option<AbortHandle>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentPool {
    /// Create an empty pool that keeps connections according to [`keeps`].
    pub(super) fn new() -> Self {
        Self::with_policy(keeps)
    }

    /// Create an empty pool with an explicit policy.
    pub(super) fn with_policy(policy: Policy) -> Self {
        Self {
            waiting: Mutex::new(HashMap::new()),
            policy,
        }
    }

    /// Take a connection for one operation on a sandbox.
    ///
    /// Hands out a waiting connection if the policy still accepts one, and dials otherwise. Two
    /// operations at once therefore get two connections. A failed dial is reported to the
    /// caller and leaves the pool as it was.
    pub(super) async fn checkout<F, Fut>(
        self: &Arc<Self>,
        sandbox_id: &str,
        dial: F,
    ) -> MicrosandboxResult<Checkout>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = MicrosandboxResult<AgentClient>>,
    {
        // Weak, so a connection that is out on loan never keeps its pool alive.
        let home = Arc::downgrade(self);

        if let Some(waiting) = self.take_waiting(sandbox_id) {
            let connection =
                AgentConnection::pooled(waiting.client, waiting.opened, sandbox_id, home);

            return Ok(Checkout {
                connection,
                reused: true,
            });
        }

        let client = dial().await?;
        let connection = AgentConnection::pooled(client, Instant::now(), sandbox_id, home);

        Ok(Checkout {
            connection,
            reused: false,
        })
    }

    /// Remove and return the sandbox's most recently used waiting connection.
    ///
    /// First closes every waiting connection, for any sandbox, that has died or that the policy
    /// no longer accepts, in case a timer could not.
    fn take_waiting(&self, sandbox_id: &str) -> Option<WaitingAgent> {
        let mut retired = Vec::new();

        let taken = {
            let mut waiting = self.waiting.lock().unwrap();
            self.retire(&mut waiting, &mut retired);

            waiting.get_mut(sandbox_id).and_then(Vec::pop)
        };

        // Closing a socket is not work to do while holding the lock.
        drop(retired);

        taken
    }

    /// Close every waiting connection, for any sandbox, that has died or that the policy no
    /// longer accepts. A waiting connection's timer calls this when its time is up.
    fn retire_expired(&self) {
        let mut retired = Vec::new();
        self.retire(&mut self.waiting.lock().unwrap(), &mut retired);

        // Closing a socket is not work to do while holding the lock.
        drop(retired);
    }

    /// Move every waiting connection that has died or that the policy no longer accepts out
    /// of `waiting` and into `retired`, for the caller to drop once the lock is released.
    fn retire(
        &self,
        waiting: &mut HashMap<String, Vec<WaitingAgent>>,
        retired: &mut Vec<WaitingAgent>,
    ) {
        let now = Instant::now();
        let wall_now = SystemTime::now();

        for (id, connections) in waiting.iter_mut() {
            let mut index = 0;
            while index < connections.len() {
                let connection = &connections[index];
                let candidate = Candidate {
                    age: now.duration_since(connection.opened),
                    idle_for: connection.idle_for(now, wall_now),
                    idle_peers: connections.len() - 1,
                };

                if !connection.client.is_closed() && self.decide(id, candidate) {
                    index += 1;
                } else {
                    retired.push(connections.remove(index));
                }
            }
        }
        waiting.retain(|_, connections| !connections.is_empty());
    }

    /// Ask the policy about one connection and record the answer.
    fn decide(&self, sandbox_id: &str, candidate: Candidate) -> bool {
        let kept = (self.policy)(&candidate);
        tracing::trace!(
            target: timing::TARGET,
            %sandbox_id,
            age_seconds = candidate.age.as_secs_f64(),
            idle_seconds = candidate.idle_for.as_secs_f64(),
            idle_peers = candidate.idle_peers,
            kept,
            "cloud agent pool decision"
        );

        kept
    }
}

impl Expiry {
    /// Start a timer that has `pool` close whatever has waited too long, once `after` has
    /// passed.
    ///
    /// A connection can be handed back on a thread that has no runtime, where no timer can
    /// run. It is then closed by the next checkout, or when the pool goes.
    fn start(pool: &Arc<AgentPool>, after: Duration) -> Self {
        let Ok(runtime) = Handle::try_current() else {
            return Self(None);
        };
        let pool = Arc::downgrade(pool);
        let timer = runtime.spawn(async move {
            tokio::time::sleep(after).await;
            if let Some(pool) = pool.upgrade() {
                pool.retire_expired();
            }
        });

        Self(Some(timer.abort_handle()))
    }
}

impl WaitingAgent {
    /// How long the connection has waited, by whichever clock says longer.
    ///
    /// The monotonic clock stops while the machine sleeps. A connection that sat through a sleep
    /// has most likely been dropped by its peer without this end hearing of it, so the wall
    /// clock gets a say. It can also be set backwards, in which case it says nothing.
    fn idle_for(&self, now: Instant, wall_now: SystemTime) -> Duration {
        let awake = now.duration_since(self.waiting_since);
        let elapsed = wall_now
            .duration_since(self.waiting_since_wall)
            .unwrap_or_default();

        awake.max(elapsed)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Expiry {
    fn drop(&mut self) {
        if let Some(timer) = self.0.take() {
            timer.abort();
        }
    }
}

impl Reclaim for AgentPool {
    fn reclaim(self: Arc<Self>, sandbox_id: &str, client: AgentClient, opened: Instant) {
        if client.is_closed() {
            return;
        }

        let now = Instant::now();
        let rejected = {
            let mut waiting = self.waiting.lock().unwrap();
            let candidate = Candidate {
                age: now.duration_since(opened),
                idle_for: Duration::ZERO,
                idle_peers: waiting.get(sandbox_id).map_or(0, Vec::len),
            };

            if self.decide(sandbox_id, candidate) {
                waiting
                    .entry(sandbox_id.to_owned())
                    .or_default()
                    .push(WaitingAgent {
                        client,
                        opened,
                        waiting_since: now,
                        waiting_since_wall: SystemTime::now(),
                        _expiry: Expiry::start(&self, MAX_IDLE),
                    });

                None
            } else {
                Some(client)
            }
        };

        // Closing a socket is not work to do while holding the lock.
        drop(rejected);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether the environment asks for connection reuse.
pub(super) fn enabled_by_env() -> bool {
    std::env::var(AGENT_REUSE_ENV).is_ok_and(|value| matches!(value.trim(), "1" | "true"))
}

/// Decide whether a connection stays in the pool.
///
/// The pool asks at two moments. When an operation finishes, `idle_for` is zero and the question
/// is whether this connection is worth keeping. Before a waiting connection is handed to the
/// next operation, the question is whether it can still be trusted.
///
/// Keeping one lets the next operation skip the upgrade through to the sandbox, which is most of
/// the cost of a short command. Operations beyond what is waiting simply dial, as they do
/// without the pool.
pub(super) fn keeps(candidate: &Candidate) -> bool {
    candidate.idle_peers < MAX_WAITING && candidate.idle_for < MAX_IDLE && candidate.age < MAX_AGE
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_protocol::{codec, exec::ExecSignal, message::MessageType};
    use tokio::io::DuplexStream;

    use super::*;
    use crate::{MicrosandboxError, test_support};

    /// Dials in-memory connections and keeps their far ends, in dial order, for a test to watch.
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

        /// Whether a frame sent on `connection` arrives at the far end of the given dial.
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

        /// Close the given dial's connection from the far side.
        async fn hang_up(&self, dial: usize) {
            self.far_ends.lock().await[dial] = None;
        }
    }

    fn keep_all(_: &Candidate) -> bool {
        true
    }

    fn keep_none(_: &Candidate) -> bool {
        false
    }

    fn keep_one_per_sandbox(candidate: &Candidate) -> bool {
        candidate.idle_peers == 0
    }

    fn keep_while_idle_under_30s(candidate: &Candidate) -> bool {
        candidate.idle_for < Duration::from_secs(30)
    }

    fn keep_while_younger_than_10m(candidate: &Candidate) -> bool {
        candidate.age < Duration::from_secs(600)
    }

    /// A connection as the pool first asks about it: just dialed, just finished, nothing waiting.
    fn just_finished() -> Candidate {
        Candidate {
            age: Duration::ZERO,
            idle_for: Duration::ZERO,
            idle_peers: 0,
        }
    }

    #[test]
    fn default_policy_lets_two_connections_wait_per_sandbox() {
        let alone = just_finished();
        let second = Candidate {
            idle_peers: 1,
            ..just_finished()
        };
        let third = Candidate {
            idle_peers: 2,
            ..just_finished()
        };

        assert!(keeps(&alone));
        assert!(keeps(&second));
        assert!(!keeps(&third));
    }

    #[test]
    fn default_policy_retires_a_connection_idle_for_thirty_seconds() {
        let still_warm = Candidate {
            idle_for: Duration::from_secs(29),
            ..just_finished()
        };
        let gone_quiet = Candidate {
            idle_for: Duration::from_secs(30),
            ..just_finished()
        };

        assert!(keeps(&still_warm));
        assert!(!keeps(&gone_quiet));
    }

    #[test]
    fn default_policy_retires_a_connection_five_minutes_old() {
        let young = Candidate {
            age: Duration::from_secs(299),
            ..just_finished()
        };
        let old = Candidate {
            age: Duration::from_secs(300),
            ..just_finished()
        };

        assert!(keeps(&young));
        assert!(!keeps(&old));
    }

    #[tokio::test]
    async fn default_pool_gives_a_finished_connection_to_the_next_operation() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(second.reused);
        assert_eq!(dialer.dials().await, 1);
    }

    #[tokio::test]
    async fn finished_connection_serves_the_next_operation() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let first_was_reused = first.reused;
        first.connection.finish();
        drop(first);
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(!first_was_reused);
        assert!(second.reused);
        assert_eq!(dialer.dials().await, 1);
        assert!(dialer.hears(0, &second.connection).await);
    }

    #[tokio::test]
    async fn abandoned_connection_is_closed_rather_than_kept() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        drop(first);
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(!second.reused);
        assert_eq!(dialer.dials().await, 2);
        dialer.expect_closed(0).await;
    }

    #[tokio::test]
    async fn operations_at_once_each_get_a_connection() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        assert_eq!(dialer.dials().await, 2);
        first.connection.finish();
        second.connection.finish();
        drop((first, second));
        let third = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let fourth = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(third.reused);
        assert!(fourth.reused);
        assert_eq!(dialer.dials().await, 2);
    }

    #[tokio::test]
    async fn most_recently_used_connection_is_handed_out_first() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let earlier = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let later = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        earlier.connection.finish();
        drop(earlier);
        later.connection.finish();
        drop(later);
        let next = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(next.reused);
        assert!(dialer.hears(1, &next.connection).await);
    }

    #[tokio::test]
    async fn connections_are_kept_per_sandbox() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let first = pool.checkout("one", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        let other = pool.checkout("two", || dialer.dial()).await.unwrap();
        let same = pool.checkout("one", || dialer.dial()).await.unwrap();

        assert!(!other.reused);
        assert!(same.reused);
        assert_eq!(dialer.dials().await, 2);
    }

    #[tokio::test]
    async fn policy_can_refuse_a_finished_connection() {
        let pool = Arc::new(AgentPool::with_policy(keep_none));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(!second.reused);
        dialer.expect_closed(0).await;
    }

    #[tokio::test]
    async fn policy_sees_how_many_connections_already_wait() {
        let pool = Arc::new(AgentPool::with_policy(keep_one_per_sandbox));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        second.connection.finish();
        drop(second);
        let third = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let fourth = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        // The first to finish waits alone and is kept; the second finds one waiting and is not.
        assert!(third.reused);
        assert!(!fourth.reused);
        assert_eq!(dialer.dials().await, 3);
        dialer.expect_closed(1).await;
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_connection_is_retired_once_the_policy_stops_accepting_it() {
        let pool = Arc::new(AgentPool::with_policy(keep_while_idle_under_30s));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        tokio::time::advance(Duration::from_secs(31)).await;
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(!second.reused);
        assert_eq!(dialer.dials().await, 2);
        dialer.expect_closed(0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_connection_is_closed_at_its_idle_limit_without_another_checkout() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let only = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        only.connection.finish();
        drop(only);

        tokio::time::sleep(MAX_IDLE - Duration::from_secs(1)).await;
        assert_eq!(
            pool.waiting.lock().unwrap().len(),
            1,
            "kept until the limit"
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(pool.waiting.lock().unwrap().is_empty());
        dialer.expect_closed(0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn connection_that_waits_again_gets_its_full_idle_time_again() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        tokio::time::sleep(Duration::from_secs(20)).await;
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        assert!(second.reused);
        second.connection.finish();
        drop(second);

        // 35 s after the first wait began, which is 15 s into the second.
        tokio::time::sleep(Duration::from_secs(15)).await;
        assert_eq!(
            pool.waiting.lock().unwrap().len(),
            1,
            "the first timer was stopped"
        );

        tokio::time::sleep(Duration::from_secs(16)).await;
        assert!(pool.waiting.lock().unwrap().is_empty());
        dialer.expect_closed(0).await;
    }

    #[tokio::test]
    async fn connection_handed_back_outside_a_runtime_waits_without_a_timer() {
        let pool = Arc::new(AgentPool::new());
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        std::thread::spawn(move || drop(first)).join().unwrap();
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(second.reused);
        assert_eq!(dialer.dials().await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn checkout_retires_waiting_connections_of_other_sandboxes() {
        let pool = Arc::new(AgentPool::with_policy(keep_while_idle_under_30s));
        let dialer = Dialer::default();

        let quiet = pool.checkout("quiet", || dialer.dial()).await.unwrap();
        quiet.connection.finish();
        drop(quiet);
        tokio::time::advance(Duration::from_secs(31)).await;
        let _busy = pool.checkout("busy", || dialer.dial()).await.unwrap();

        dialer.expect_closed(0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn age_counts_from_the_dial_across_uses() {
        let pool = Arc::new(AgentPool::with_policy(keep_while_younger_than_10m));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        tokio::time::advance(Duration::from_secs(360)).await;
        first.connection.finish();
        drop(first);
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        let second_was_reused = second.reused;
        tokio::time::advance(Duration::from_secs(360)).await;
        second.connection.finish();
        drop(second);
        let third = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        // Six minutes old it is kept; twelve minutes old, on its second use, it is not.
        assert!(second_was_reused);
        assert!(!third.reused);
        dialer.expect_closed(0).await;
    }

    #[tokio::test]
    async fn idle_time_includes_time_the_machine_spent_asleep() {
        let (client, _far_end) = test_support::agent_client_pair().await;
        let now = Instant::now();
        let wall_now = SystemTime::now();
        let hour = Duration::from_secs(3600);
        let slept_through = WaitingAgent {
            client,
            opened: now,
            waiting_since: now,
            waiting_since_wall: wall_now - hour,
            _expiry: Expiry(None),
        };

        // No monotonic time has passed, as after a sleep, but the wall clock moved on.
        assert_eq!(slept_through.idle_for(now, wall_now), hour);
        assert_eq!(
            slept_through.idle_for(now, wall_now - 2 * hour),
            Duration::ZERO,
            "a wall clock set backwards says nothing"
        );
    }

    #[tokio::test]
    async fn dead_waiting_connection_is_not_handed_out() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        first.connection.finish();
        drop(first);
        dialer.hang_up(0).await;
        // Give the waiting connection's reader a turn to see the far end go.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(!second.reused);
        assert_eq!(dialer.dials().await, 2);
    }

    #[tokio::test]
    async fn failed_dial_is_reported_and_the_pool_still_works() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let failed = pool
            .checkout("sandbox", || async {
                Err(MicrosandboxError::Runtime("unreachable".into()))
            })
            .await;
        let next = pool.checkout("sandbox", || dialer.dial()).await.unwrap();

        assert!(failed.is_err());
        assert!(!next.reused);
    }

    #[tokio::test]
    async fn connection_that_outlives_its_pool_is_closed() {
        let pool = Arc::new(AgentPool::with_policy(keep_all));
        let dialer = Dialer::default();

        let first = pool.checkout("sandbox", || dialer.dial()).await.unwrap();
        drop(pool);
        first.connection.finish();
        drop(first);

        dialer.expect_closed(0).await;
    }
}
