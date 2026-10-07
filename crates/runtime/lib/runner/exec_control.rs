//! Ephemeral authority for signals that bypass a backpressured agent socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_protocol::exec::ExecSignal;
use microsandbox_protocol::exec_control::{
    EXEC_CONTROL_VERSION, ExecControlRequest, ExecControlResponse,
};
use microsandbox_protocol::{
    codec,
    message::{Message, MessageType},
};
use rand::RngExt as _;
use tokio::sync::{Notify, oneshot};

use super::relay::{ControlWrite, ControlWriter};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DELIVERY_DEADLINE: Duration = Duration::from_secs(3);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One relay lifetime; tokens are never reused across restart or restore.
#[derive(Default)]
pub(crate) struct ExecControlRegistry {
    clients: Mutex<HashMap<[u8; 16], Arc<Owner>>>,
    /// Enabled only after the guest acknowledges its bounded input and range-lease contracts.
    pub(crate) enabled: AtomicBool,
    pub(crate) stopping: AtomicBool,
}

struct Owner {
    start: u32,
    end: u32,
    live: AtomicBool,
    changed: Notify,
    executions: Mutex<HashMap<u32, Arc<ExecControlLease>>>,
}

/// Dropping the primary connection revokes its sideband authority before slot reuse.
pub(crate) struct ExecControlConnection {
    token: [u8; 16],
    owner: Arc<Owner>,
    registry: Weak<ExecControlRegistry>,
}

/// Attached to a queued signal so retirement also invalidates previously admitted requests.
pub(crate) struct ExecControlLease {
    live: AtomicBool,
    started: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecControlRegistry {
    pub(crate) fn connect(self: &Arc<Self>, start: u32, end: u32) -> ExecControlConnection {
        let owner = Arc::new(Owner {
            start,
            end,
            live: AtomicBool::new(true),
            changed: Notify::new(),
            executions: Mutex::new(HashMap::new()),
        });
        let mut clients = self.clients.lock().unwrap();
        let token = loop {
            let token = rand::rng().random::<[u8; 16]>();
            if !clients.contains_key(&token) {
                break token;
            }
        };
        clients.insert(token, Arc::clone(&owner));
        ExecControlConnection {
            token,
            owner,
            registry: Arc::downgrade(self),
        }
    }

    pub(crate) async fn signal(
        &self,
        writer: &ControlWriter,
        request: ExecControlRequest,
    ) -> ExecControlResponse {
        if request.version != EXEC_CONTROL_VERSION {
            return ExecControlResponse::error(
                "unsupported_feature",
                "unsupported exec control contract",
            );
        }
        // Ordinary exec historically accepted zero. This preserves that input without
        // promising a liveness query: delivery still does not acknowledge guest handling.
        if !(0..=64).contains(&request.signal) {
            return ExecControlResponse::error("invalid_signal", "signal must be between 0 and 64");
        }
        let owner = {
            let clients = self.clients.lock().unwrap();
            let Some(owner) = clients.get(&request.connection) else {
                return ExecControlResponse::error(
                    "execution_closed",
                    "the owning agent connection has ended",
                );
            };
            if !(owner.start..owner.end).contains(&request.id) {
                return ExecControlResponse::error(
                    "execution_closed",
                    "execution does not belong to this connection",
                );
            }
            Arc::clone(owner)
        };
        let delivered = async {
            // The separate sockets can race, including an immediate kill after exec() returns.
            // Wait for this owner's actual ExecStarted rather than overtaking process creation.
            // Once captured, retain the same lease through terminal/disconnect; never retarget it.
            let mut lease = None;
            let lease = loop {
                let changed = owner.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !owner.live.load(Ordering::Acquire) {
                    return Err("the owning agent connection has ended".to_string());
                }
                if lease.is_none() {
                    lease = owner.executions.lock().unwrap().get(&request.id).cloned();
                }
                if let Some(lease) = lease.as_ref() {
                    if !lease.live() {
                        return Err("execution has ended".to_string());
                    }
                    if lease.started.load(Ordering::Acquire) {
                        break Arc::clone(lease);
                    }
                }
                changed.await;
            };
            let message = Message::with_payload(
                MessageType::ExecSignal,
                request.id,
                &ExecSignal {
                    signal: request.signal,
                },
            )
            .map_err(|error| error.to_string())?;
            let mut data = Vec::new();
            codec::encode_to_buf(&message, &mut data).map_err(|error| error.to_string())?;
            let (completion, completed) = oneshot::channel();
            let write = ControlWrite::exec_signal(Bytes::from(data), request.id, lease, completion);
            writer
                .send(write)
                .await
                .map_err(|_| "exec control transport is closed".to_string())?;
            completed.await.map_err(|_| {
                "execution ended or its transport closed before delivery confirmation".to_string()
            })
        };
        match tokio::time::timeout(DELIVERY_DEADLINE, delivered).await {
            Ok(Ok(())) => ExecControlResponse::delivered(),
            Ok(Err(error)) => ExecControlResponse::error("delivery_unconfirmed", error),
            Err(_) => ExecControlResponse::error(
                "delivery_unconfirmed",
                "signal delivery deadline expired; an admitted request may still be delivered",
            ),
        }
    }
}

impl ExecControlConnection {
    pub(crate) fn token(&self) -> [u8; 16] {
        self.token
    }

    pub(crate) fn register(&self, id: u32) {
        let mut executions = self.owner.executions.lock().unwrap();
        // Never replace a live identity if a malformed client reuses a correlation.
        executions.entry(id).or_insert_with(|| {
            Arc::new(ExecControlLease {
                live: AtomicBool::new(true),
                started: AtomicBool::new(false),
            })
        });
        drop(executions);
        self.owner.changed.notify_waiters();
    }

    pub(crate) fn pending(&self, id: u32) -> bool {
        self.owner
            .executions
            .lock()
            .unwrap()
            .get(&id)
            .is_some_and(|lease| !lease.started.load(Ordering::Acquire))
    }

    pub(crate) fn started(&self, id: u32) {
        if let Some(lease) = self.owner.executions.lock().unwrap().get(&id) {
            lease.started.store(true, Ordering::Release);
        }
        self.owner.changed.notify_waiters();
    }

    pub(crate) fn retire(&self, id: u32) {
        if let Some(lease) = self.owner.executions.lock().unwrap().remove(&id) {
            lease.live.store(false, Ordering::Release);
        }
        self.owner.changed.notify_waiters();
    }
}

impl ExecControlLease {
    pub(crate) fn live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ExecControlConnection {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            // Revoke first; an in-flight handler holding a lease is fenced separately below.
            registry.clients.lock().unwrap().remove(&self.token);
        }
        self.owner.live.store(false, Ordering::Release);
        for lease in self.owner.executions.lock().unwrap().values() {
            lease.live.store(false, Ordering::Release);
        }
        self.owner.changed.notify_waiters();
    }
}
