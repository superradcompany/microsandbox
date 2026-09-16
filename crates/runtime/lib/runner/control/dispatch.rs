//! Fair serialized host dispatch with pre-reserved response capacity.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};

use microsandbox_protocol::{
    codec::{self, RawFrame},
    control::*,
    wire::Envelope,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use super::handler::{Handler, Reply};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const CONNECTION_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const RUNTIME_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_QUEUED: usize = 256;
// Generation-one replies contain only fixed records and static diagnostics.
// This reservation is acquired before dispatching even a resource mutation.
pub(crate) const REPLY_BYTES: u32 = MAX_HANDSHAKE_FRAME_SIZE + 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct Dispatcher {
    handler: Arc<dyn Handler>,
    queues: Mutex<Queues>,
    wake: Notify,
    pub bytes: Arc<Semaphore>,
}

#[derive(Default)]
struct Queues {
    by_connection: HashMap<u64, VecDeque<Job>>,
    ready: VecDeque<u64>,
    count: usize,
}

pub(crate) struct Budget {
    _connection: OwnedSemaphorePermit,
    _runtime: OwnedSemaphorePermit,
}

pub(crate) struct Lease {
    id: Option<u32>,
    ids: Arc<Mutex<HashSet<u32>>>,
    permit: Option<OwnedSemaphorePermit>,
}

pub(crate) enum Input {
    #[cfg(test)]
    Json(ControlRequest),
    JsonWire(serde_json::Value, Option<std::fs::File>),
    Framed {
        frame: RawFrame,
        generation: u8,
        _budget: Budget,
    },
}

pub(crate) struct Job {
    pub input: Input,
    pub reply: mpsc::Sender<Outgoing>,
    pub output_budget: Option<Budget>,
    pub lease: Option<Lease>,
    pub cancelled: CancellationToken,
}

pub(crate) struct Outgoing {
    pub bytes: Vec<u8>,
    pub _budget: Option<Budget>,
    pub lease: Option<Lease>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Dispatcher {
    pub fn new(handler: Arc<dyn Handler>) -> Arc<Self> {
        Arc::new(Self {
            handler,
            queues: Mutex::new(Queues::default()),
            wake: Notify::new(),
            bytes: Arc::new(Semaphore::new(RUNTIME_BYTES)),
        })
    }

    pub fn submit(&self, connection: u64, job: Job) -> Result<(), Box<Job>> {
        let mut queues = self.queues.lock().unwrap();
        if queues.count >= MAX_QUEUED {
            return Err(Box::new(job));
        }
        let queue = queues.by_connection.entry(connection).or_default();
        let newly_ready = queue.is_empty();
        queue.push_back(job);
        if newly_ready {
            queues.ready.push_back(connection);
        }
        queues.count += 1;
        drop(queues);
        self.wake.notify_one();
        Ok(())
    }

    pub fn cancel(&self, connection: u64) {
        let mut queues = self.queues.lock().unwrap();
        if let Some(jobs) = queues.by_connection.remove(&connection) {
            queues.count -= jobs.len();
        }
        queues.ready.retain(|id| *id != connection);
    }

    fn next(&self) -> Option<Job> {
        let mut queues = self.queues.lock().unwrap();
        let connection = queues.ready.pop_front()?;
        let queue = queues.by_connection.get_mut(&connection).unwrap();
        let job = queue.pop_front().unwrap();
        if queue.is_empty() {
            queues.by_connection.remove(&connection);
        } else {
            queues.ready.push_back(connection);
        }
        queues.count -= 1;
        Some(job)
    }

    pub async fn run(self: Arc<Self>) {
        loop {
            let notified = self.wake.notified();
            if let Some(job) = self.next() {
                if !job.cancelled.is_cancelled() {
                    let dispatcher = self.clone();
                    let _ = tokio::task::spawn_blocking(move || dispatcher.execute(job)).await;
                }
                // Let accept/read/write tasks enqueue other ready connections.
                // FIFO within each connection plus round-robin above is fair.
                tokio::task::yield_now().await;
            } else {
                notified.await;
            }
        }
    }

    fn execute(&self, job: Job) {
        let bytes = match &job.input {
            Input::JsonWire(_, _) => {
                let Input::JsonWire(value, memory) = job.input else {
                    unreachable!()
                };
                Ok(self.handler.handle_json_with_memory(value, memory))
            }
            #[cfg(test)]
            Input::Json(_) => {
                let Input::Json(request) = job.input else {
                    unreachable!()
                };
                let response = self.handler.handle(request);
                let mut bytes = serde_json::to_vec(&response.json).unwrap_or_default();
                bytes.push(b'\n');
                Ok(bytes)
            }
            Input::Framed {
                frame, generation, ..
            } => self.framed(frame, *generation),
        };
        match bytes {
            Ok(bytes) => {
                let outgoing = Outgoing {
                    bytes,
                    _budget: job.output_budget,
                    lease: job.lease,
                };
                if job.reply.try_send(outgoing).is_err() {
                    job.cancelled.cancel();
                }
            }
            Err(_) => job.cancelled.cancel(),
        }
    }

    fn framed(&self, frame: &RawFrame, generation: u8) -> io::Result<Vec<u8>> {
        let envelope = Envelope::decode(&frame.body).map_err(|_| invalid())?;
        let reply = if envelope.v != generation || frame.flags != 0 {
            Reply::Error(ControlError::rejected(
                "invalid_request",
                "invalid control generation or flags",
            ))
        } else if matches!(envelope.t.as_str(), "control.hello" | "control.welcome") {
            // Repeated setup cannot reset the parser, IDs, or negotiated limits.
            return Err(invalid());
        } else if !ControlMessageType::from_wire_str(&envelope.t)
            .is_some_and(ControlMessageType::is_request)
        {
            Reply::Error(ControlError::rejected(
                "unsupported_operation",
                "unknown control operation",
            ))
        } else {
            match ControlRequest::from_envelope(&envelope) {
                Ok(request) => self.handler.handle(request).framed,
                Err(_) => Reply::Error(ControlError::rejected(
                    "invalid_request",
                    "invalid control request payload",
                )),
            }
        };
        framed_reply(&reply, generation, frame.id)
    }
}

impl Budget {
    pub async fn acquire(
        connection: &Arc<Semaphore>,
        runtime: &Arc<Semaphore>,
        bytes: u32,
    ) -> io::Result<Self> {
        let local = Arc::clone(connection)
            .acquire_many_owned(bytes)
            .await
            .map_err(|_| invalid())?;
        let global = Arc::clone(runtime)
            .acquire_many_owned(bytes)
            .await
            .map_err(|_| invalid())?;
        Ok(Self {
            _connection: local,
            _runtime: global,
        })
    }

    pub fn reserve_reply(
        connection: &Arc<Semaphore>,
        runtime: &Arc<Semaphore>,
    ) -> io::Result<Self> {
        let local = Arc::clone(connection)
            .try_acquire_many_owned(REPLY_BYTES)
            .map_err(|_| invalid())?;
        let global = Arc::clone(runtime)
            .try_acquire_many_owned(REPLY_BYTES)
            .map_err(|_| invalid())?;
        Ok(Self {
            _connection: local,
            _runtime: global,
        })
    }
}

impl Lease {
    pub fn acquire(
        id: u32,
        ids: &Arc<Mutex<HashSet<u32>>>,
        capacity: &Arc<Semaphore>,
    ) -> io::Result<Self> {
        if id == 0 {
            return Err(invalid());
        }
        let permit = Arc::clone(capacity)
            .try_acquire_owned()
            .map_err(|_| invalid())?;
        if !ids.lock().unwrap().insert(id) {
            return Err(invalid());
        }
        Ok(Self {
            id: Some(id),
            ids: Arc::clone(ids),
            permit: Some(permit),
        })
    }

    pub fn terminal_admitted(&mut self) {
        // Remove before starting the terminal write: the peer may receive it
        // before our write future wakes. Its next legitimate ID reuse is valid.
        if let Some(id) = self.id.take() {
            self.ids.lock().unwrap().remove(&id);
        }
        self.permit.take();
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Lease {
    fn drop(&mut self) {
        self.terminal_admitted();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn framed_reply(reply: &Reply, generation: u8, id: u32) -> io::Result<Vec<u8>> {
    let frame = reply
        .envelope(generation)
        .and_then(|envelope| envelope.frame(id, 1))
        .map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    codec::encode_raw_to_buf(&frame, &mut bytes).map_err(|_| invalid())?;
    if bytes.len() > REPLY_BYTES as usize {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(crate) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unavailable control exchange",
    )
}
