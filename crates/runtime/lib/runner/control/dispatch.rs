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
const MAX_SIGNAL_QUEUED: usize = 64;
// Generation-one replies contain only fixed records and static diagnostics.
// This reservation is acquired before dispatching even a resource mutation.
pub(crate) const REPLY_BYTES: u32 = MAX_HANDSHAKE_FRAME_SIZE + 4;
/// Ordinary generation-two state replies may contain several host paths and diagnostics.
pub(crate) const EXTENDED_REPLY_BYTES: u32 = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct Dispatcher {
    handler: Arc<dyn Handler>,
    queues: Mutex<Queues>,
    wake: Notify,
    signal_queues: Mutex<Queues>,
    signal_wake: Notify,
    connection_lanes: Mutex<HashMap<u64, bool>>,
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
        reply_limit: u32,
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
            signal_queues: Mutex::new(Queues::default()),
            signal_wake: Notify::new(),
            connection_lanes: Mutex::new(HashMap::new()),
            bytes: Arc::new(Semaphore::new(RUNTIME_BYTES)),
        })
    }

    pub fn submit(&self, connection: u64, job: Job) -> Result<(), Box<Job>> {
        let signal = *self.connection_lanes.lock().unwrap().entry(connection).or_insert_with(|| {
            matches!(&job.input, Input::Framed { frame, generation, .. }
                if *generation >= 2 && Envelope::decode(&frame.body).is_ok_and(|envelope| envelope.t == microsandbox_protocol::exec_control::EXEC_CONTROL_REQUEST))
        });
        // A connection keeps one lane for its whole lifetime, preserving its FIFO even when a
        // low-level client mixes operations. The native signal helper uses a dedicated connection.
        let (queue, wake, limit) = if signal {
            (&self.signal_queues, &self.signal_wake, MAX_SIGNAL_QUEUED)
        } else {
            (&self.queues, &self.wake, MAX_QUEUED)
        };
        let mut queues = queue.lock().unwrap();
        if queues.count >= limit {
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
        wake.notify_one();
        Ok(())
    }

    pub fn cancel(&self, connection: u64) {
        self.connection_lanes.lock().unwrap().remove(&connection);
        for queue in [&self.queues, &self.signal_queues] {
            let mut queues = queue.lock().unwrap();
            if let Some(jobs) = queues.by_connection.remove(&connection) {
                queues.count -= jobs.len();
            }
            queues.ready.retain(|id| *id != connection);
        }
    }

    fn next_lane(&self, signal: bool) -> Option<Job> {
        let mut queues = if signal {
            &self.signal_queues
        } else {
            &self.queues
        }
        .lock()
        .unwrap();
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
        // A paused signal waiting for guest delivery must not prevent Resume from dispatching.
        // Both lanes stay bounded and lifecycle mutation still enters the runtime executor.
        tokio::join!(self.clone().run_lane(false), self.run_lane(true));
    }

    async fn run_lane(self: Arc<Self>, signal: bool) {
        loop {
            let notified = if signal {
                &self.signal_wake
            } else {
                &self.wake
            }
            .notified();
            if let Some(job) = self.next_lane(signal) {
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
                let response = self
                    .handler
                    .handle(ControlOperation::GenerationOne(request), 1);
                let mut bytes = serde_json::to_vec(&response.json).unwrap_or_default();
                bytes.push(b'\n');
                Ok(bytes)
            }
            Input::Framed {
                frame,
                generation,
                reply_limit,
                ..
            } => self.framed(frame, *generation, *reply_limit),
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

    fn framed(&self, frame: &RawFrame, generation: u8, reply_limit: u32) -> io::Result<Vec<u8>> {
        let envelope = Envelope::decode(&frame.body).map_err(|_| invalid())?;
        let reply = if envelope.v != generation || frame.flags != 0 {
            Reply::Error(ControlError::rejected(
                "invalid_request",
                "invalid control generation or flags",
            ))
        } else if matches!(envelope.t.as_str(), "control.hello" | "control.welcome") {
            // Repeated setup cannot reset the parser, IDs, or negotiated limits.
            return Err(invalid());
        } else if envelope.t == microsandbox_protocol::exec_control::EXEC_CONTROL_REQUEST
            && generation >= 2
        {
            match envelope.payload::<microsandbox_protocol::exec_control::ExecControlRequest>() {
                Ok(request) => Reply::ExecSignal(self.handler.handle_exec_signal(request)),
                Err(_) => Reply::Error(ControlError::rejected(
                    "invalid_request",
                    "invalid exec control payload",
                )),
            }
        } else if envelope.t == microsandbox_protocol::jobs::JOB_REQUEST && generation >= 2 {
            // Keep the released, exhaustively matchable control enums source-compatible.
            match envelope.payload::<microsandbox_protocol::jobs::JobRequest>() {
                Ok(request) => Reply::Job(self.handler.handle_job(request)),
                Err(_) => Reply::Error(ControlError::rejected(
                    "invalid_request",
                    "invalid job request payload",
                )),
            }
        } else {
            match ControlOperation::from_envelope(&envelope, generation) {
                Ok(request) => self.handler.handle(request, generation).framed,
                Err(_)
                    if control_message_min_generation(&envelope.t)
                        .is_some_and(|minimum| minimum > generation) =>
                {
                    Reply::Error(ControlError::rejected(
                        "unsupported_operation",
                        "operation requires a newer negotiated control generation",
                    ))
                }
                Err(_) if control_message_min_generation(&envelope.t).is_none() => {
                    Reply::Error(ControlError::rejected(
                        "unsupported_operation",
                        "unknown or unavailable control operation",
                    ))
                }
                Err(_) => Reply::Error(ControlError::rejected(
                    "invalid_request",
                    "invalid control request payload",
                )),
            }
        };
        framed_reply(&reply, generation, frame.id, reply_limit)
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
        bytes: u32,
    ) -> io::Result<Self> {
        let local = Arc::clone(connection)
            .try_acquire_many_owned(bytes)
            .map_err(|_| invalid())?;
        let global = Arc::clone(runtime)
            .try_acquire_many_owned(bytes)
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

pub(crate) fn framed_reply(
    reply: &Reply,
    generation: u8,
    id: u32,
    reply_limit: u32,
) -> io::Result<Vec<u8>> {
    let frame = reply
        .envelope(generation)
        .and_then(|envelope| envelope.frame(id, 1))
        .map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    codec::encode_raw_to_buf(&frame, &mut bytes).map_err(|_| invalid())?;
    if bytes.len() > reply_limit as usize {
        return Err(invalid());
    }
    Ok(bytes)
}

/// Reserve against the largest reply admitted by this operation before dispatch mutates state.
pub(crate) fn reply_bytes(frame: &RawFrame, generation: u8) -> io::Result<u32> {
    if generation < 2 {
        return Ok(REPLY_BYTES);
    }
    let envelope = Envelope::decode(&frame.body).map_err(|_| invalid())?;
    Ok(match envelope.t.as_str() {
        // The result contains one entry per selected disk and can legitimately approach the
        // negotiated frame ceiling. Reserving it here prevents mutation without reply capacity.
        "control.disk.checkpoint.create" | "control.disk.compact" => codec::MAX_FRAME_SIZE + 4,
        // Job metadata, list pages, and replay chunks are bounded below this ceiling.
        // Reserving a full frame here would close an 8 MiB session on two overlapping reads.
        "control.jobs" => microsandbox_protocol::jobs::JOB_REPLY_BYTES,
        _ => EXTENDED_REPLY_BYTES,
    })
}

pub(crate) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or unavailable control exchange",
    )
}
