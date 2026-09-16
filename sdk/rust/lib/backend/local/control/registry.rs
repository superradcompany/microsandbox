//! One bounded registry per backend, with shared setup and independent waiters.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};

use microsandbox_control_client::{
    ClientError, ControlClientError, ControlConnection, ErrorKind, VerifiedControlConnector,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::identity::{DatabaseIdentity, ProcessStart};
use super::session::ControlSession;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_SESSIONS: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct RuntimeKey {
    pub sandbox_id: i32,
    pub run_id: i32,
    pub pid: i32,
    pub start: ProcessStart,
}

pub(super) type SharedError = Arc<ControlClientError>;
type Entries = Mutex<HashMap<RuntimeKey, Arc<Entry>>>;

pub(crate) struct ControlSessions {
    entries: Arc<Entries>,
    database: Mutex<Option<Arc<DatabaseIdentity>>>,
    limit: usize,
}

pub(super) struct Entry {
    pub key: RuntimeKey,
    state: Mutex<EntryState>,
    changed: Notify,
    pub invalidated: CancellationToken,
    pub connector: Arc<dyn VerifiedControlConnector>,
}

enum EntryState {
    Connecting { waiters: usize },
    Ready(ControlConnection),
    Invalid(SharedError),
}

struct Waiter(Arc<Entry>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlSessions {
    /// Called when this backend opens its database, not each time a path is reused.
    pub fn bind_database(&self, path: &Path) -> Result<(), SharedError> {
        let identity = Arc::new(DatabaseIdentity::capture(path).map_err(Arc::new)?);
        let existing = self
            .database
            .lock()
            .unwrap()
            .get_or_insert(identity)
            .clone();
        existing.verify().map_err(Arc::new)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn with_limit(limit: usize) -> Self {
        let mut registry = Self::default();
        registry.limit = limit;
        registry
    }

    pub(super) fn database(&self) -> Result<Arc<DatabaseIdentity>, SharedError> {
        let database = self.database.lock().unwrap().clone().ok_or_else(changed)?;
        if let Err(error) = database.verify() {
            self.invalidate_all();
            return Err(Arc::new(error));
        }
        Ok(database)
    }

    pub(super) async fn get(
        &self,
        key: RuntimeKey,
        connector: Arc<dyn VerifiedControlConnector>,
    ) -> Result<ControlSession, SharedError> {
        // Retire known dead entries before testing capacity. No registry lock
        // crosses verification I/O, and no live entry is evicted to make space.
        let candidates = {
            let entries = self.entries.lock().unwrap();
            entries
                .iter()
                .filter(|(old, entry)| {
                    old.sandbox_id == key.sandbox_id && **old != key
                        || entry.is_closed()
                        || entries.len() >= self.limit
                })
                .map(|(key, entry)| (*key, entry.clone()))
                .collect::<Vec<_>>()
        };
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        for (old, entry) in candidates {
            // A different key may come from a delayed lookup of a previous
            // run. Verify the cached owner before retiring its session so a
            // stale caller cannot cancel the current run's work or setup.
            let failed = if entry.is_closed() {
                true
            } else {
                match tokio::time::timeout_at(until, entry.connector.verify_session(until)).await {
                    Ok(result) => result.is_err(),
                    Err(_) => return Err(Arc::new(ClientError::new(ErrorKind::Timeout).into())),
                }
            };
            if failed {
                let mut entries = self.entries.lock().unwrap();
                if entries
                    .get(&old)
                    .is_some_and(|current| Arc::ptr_eq(current, &entry))
                {
                    entries.remove(&old);
                    entry.invalidate(changed());
                }
            }
        }
        let (entry, start) = {
            let mut entries = self.entries.lock().unwrap();
            if let Some(entry) = entries.get(&key) {
                let mut state = entry.state.lock().unwrap();
                match &mut *state {
                    EntryState::Ready(connection) if !connection.is_closed() => {
                        return Ok(ControlSession::new(entry.clone(), connection.clone()));
                    }
                    EntryState::Connecting { waiters } => {
                        *waiters += 1;
                        (entry.clone(), false)
                    }
                    _ => return Err(changed()),
                }
            } else {
                if entries.len() >= self.limit {
                    return Err(Arc::new(ClientError::new(ErrorKind::Capacity).into()));
                }
                let entry = Arc::new(Entry {
                    key,
                    state: Mutex::new(EntryState::Connecting { waiters: 1 }),
                    changed: Notify::new(),
                    invalidated: CancellationToken::new(),
                    connector,
                });
                entries.insert(key, entry.clone());
                (entry, true)
            }
        };
        let waiter = Waiter(entry.clone());
        if start {
            tokio::spawn(entry.run(Arc::downgrade(&self.entries)));
        }
        waiter.wait().await
    }

    pub fn invalidate_sandbox(&self, sandbox_id: i32) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|key, entry| {
            if key.sandbox_id != sandbox_id {
                return true;
            }
            entry.invalidate(changed());
            false
        });
    }

    fn invalidate_all(&self) {
        let mut entries = self.entries.lock().unwrap();
        for (_, entry) in entries.drain() {
            entry.invalidate(changed());
        }
    }
}

impl Entry {
    pub fn invalidate(&self, error: SharedError) {
        *self.state.lock().unwrap() = EntryState::Invalid(error);
        self.invalidated.cancel();
        self.changed.notify_waiters();
    }

    pub fn is_closed(&self) -> bool {
        if self.invalidated.is_cancelled() {
            return true;
        }
        match &*self.state.lock().unwrap() {
            EntryState::Ready(connection) => connection.is_closed(),
            EntryState::Invalid(_) => true,
            EntryState::Connecting { .. } => false,
        }
    }

    async fn run(self: Arc<Self>, registry: Weak<Entries>) {
        self.clone().run_connection().await;
        // A weak reference avoids retaining the backend. Compare the entry
        // too: completion of an old worker cannot remove a replacement session.
        if let Some(registry) = registry.upgrade() {
            let mut entries = registry.lock().unwrap();
            if entries
                .get(&self.key)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self))
            {
                entries.remove(&self.key);
            }
        }
    }

    async fn run_connection(self: Arc<Self>) {
        let result = tokio::select! {
            biased;
            _ = self.invalidated.cancelled() => return,
            result = ControlConnection::connect_verified_connector(self.connector.clone()) => result,
        };
        let connection = match result {
            Ok(connection) => connection,
            Err(error) => {
                self.invalidate(Arc::new(error));
                return;
            }
        };
        {
            let mut state = self.state.lock().unwrap();
            if !self.invalidated.is_cancelled() {
                *state = EntryState::Ready(connection.clone());
            }
        }
        self.changed.notify_waiters();
        // This worker holds the connection until invalidation. Backend drop,
        // stop, and transport failure all wake it; no backend Arc cycle exists.
        tokio::select! {
            biased;
            _ = self.invalidated.cancelled() => {},
            _ = connection.closed() => self.invalidate(Arc::new(ClientError::new(ErrorKind::Closed).into())),
        }
        connection.close().await;
    }
}

impl Waiter {
    async fn wait(self) -> Result<ControlSession, SharedError> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match &*self.0.state.lock().unwrap() {
                EntryState::Ready(connection) => {
                    return Ok(ControlSession::new(self.0.clone(), connection.clone()));
                }
                EntryState::Invalid(error) => return Err(error.clone()),
                EntryState::Connecting { .. } => {}
            }
            changed.await;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ControlSessions {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            database: Mutex::new(None),
            limit: MAX_SESSIONS,
        }
    }
}

impl Drop for ControlSessions {
    fn drop(&mut self) {
        self.invalidate_all();
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        if let EntryState::Connecting { waiters } = &mut *state {
            *waiters -= 1;
            if *waiters == 0 {
                *state = EntryState::Invalid(Arc::new(ClientError::new(ErrorKind::Closed).into()));
                self.0.invalidated.cancel();
                self.0.changed.notify_waiters();
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn changed() -> SharedError {
    Arc::new(ControlClientError::RuntimeChanged)
}
