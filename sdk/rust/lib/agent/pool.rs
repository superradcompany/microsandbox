//! Exclusive reuse of completed Cloud exec connections. Cancellation drops the
//! transport, retaining the relay's disconnect cleanup for active commands.

use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use microsandbox_agent_client::AgentClient as Transport;
use tokio::time::Instant;

use super::AgentClient;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LIFETIME: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One idle connection per immutable sandbox handle; active leases never queue.
#[derive(Default)]
pub(crate) struct AgentPool {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    generation: Arc<()>,
    idle: Option<Idle>,
    expiry_task: Option<tokio::task::JoinHandle<()>>,
}

struct Idle {
    client: Transport,
    created: Instant,
    expires: Instant,
}

/// Authority to return one finished connection to the generation that leased it.
pub(crate) struct ReturnTicket {
    pool: Weak<AgentPool>,
    generation: Arc<()>,
    created: Instant,
    completed: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentPool {
    pub(crate) fn ticket(self: &Arc<Self>) -> ReturnTicket {
        ReturnTicket {
            pool: Arc::downgrade(self),
            generation: self
                .state
                .lock()
                .expect("agent pool poisoned")
                .generation
                .clone(),
            created: Instant::now(),
            completed: AtomicBool::new(false),
        }
    }

    pub(crate) fn take(self: &Arc<Self>) -> Option<AgentClient> {
        let mut state = self.state.lock().expect("agent pool poisoned");
        let idle = state.idle.take()?;
        if idle.expires <= Instant::now() || idle.client.is_closed() {
            return None;
        }
        let ticket = ReturnTicket {
            pool: Arc::downgrade(self),
            generation: state.generation.clone(),
            created: idle.created,
            completed: AtomicBool::new(false),
        };
        Some(AgentClient::from_inner(idle.client).with_return_ticket(ticket))
    }

    /// Old active leases may finish but cannot repopulate the invalidated pool.
    pub(crate) fn invalidate(&self) {
        let mut state = self.state.lock().expect("agent pool poisoned");
        state.generation = Arc::new(());
        state.idle = None;
    }

    fn expire(&self, now: Instant) {
        let mut state = self.state.lock().expect("agent pool poisoned");
        if state.idle.as_ref().is_some_and(|idle| idle.expires <= now) {
            state.idle = None;
        }
    }
}

impl ReturnTicket {
    pub(super) fn complete(&self) {
        self.completed.store(true, Ordering::Relaxed);
    }

    pub(super) fn recycle(self, client: Transport) {
        if !self.completed.load(Ordering::Relaxed) || client.is_closed() {
            return;
        }
        let Some(pool) = self.pool.upgrade() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let now = Instant::now();
        let expires = (now + IDLE_TIMEOUT).min(self.created + MAX_LIFETIME);
        if expires <= now {
            return;
        }
        let mut state = pool.state.lock().expect("agent pool poisoned");
        if !Arc::ptr_eq(&state.generation, &self.generation) {
            return;
        }
        // At most one idle transport and one expiry task per handle.
        state.idle = Some(Idle {
            client,
            created: self.created,
            expires,
        });
        if state
            .expiry_task
            .as_ref()
            .is_none_or(|task| task.is_finished())
        {
            let weak = Arc::downgrade(&pool);
            state.expiry_task = Some(runtime.spawn(async move {
                loop {
                    let Some(pool) = weak.upgrade() else {
                        return;
                    };
                    let deadline = {
                        let mut state = pool.state.lock().expect("agent pool poisoned");
                        match &state.idle {
                            Some(idle) => idle.expires,
                            None => {
                                state.expiry_task = None;
                                return;
                            }
                        }
                    };
                    drop(pool);
                    tokio::time::sleep_until(deadline).await;
                    if let Some(pool) = weak.upgrade() {
                        pool.expire(Instant::now());
                    }
                }
            }));
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
