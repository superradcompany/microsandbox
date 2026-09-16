//! One reader, one writer, bounded queues, and connection-local ID ownership.

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use microsandbox_protocol::message::FLAG_TERMINAL;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use zeroize::Zeroizing;

use crate::{ClientError, ClientLimits, ClientResult, Delivery, ErrorKind, IdRange, RawFrame};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct State {
    routing: Mutex<Routing>,
    pub(crate) budget: Arc<Semaphore>,
    pub(crate) limits: ClientLimits,
    stopped: watch::Sender<bool>,
}

struct Routing {
    ids: IdRange,
    next: u64,
    reuse_ids: bool,
    pending: HashMap<u32, Entry>,
    failure: Option<ErrorKind>,
}

struct Entry {
    lease: Arc<Lease>,
    // None is a draining subscription. Its ID remains reserved until terminal.
    sender: Option<mpsc::Sender<QueuedFrame>>,
}

pub(crate) struct Lease {
    pub(crate) id: u32,
    admitted: AtomicBool,
    pub(crate) terminal: AtomicBool,
}

pub(crate) struct QueuedFrame {
    pub(crate) frame: RawFrame,
    _bytes: OwnedSemaphorePermit,
}

pub(crate) struct WriteCommand {
    pub(crate) packet: Zeroizing<Vec<u8>>,
    pub(crate) ack: oneshot::Sender<ClientResult<()>>,
    pub(crate) _bytes: OwnedSemaphorePermit,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl State {
    pub(crate) fn new(ids: IdRange, limits: ClientLimits, reuse_ids: bool) -> Arc<Self> {
        let (stopped, _) = watch::channel(false);
        Arc::new(Self {
            routing: Mutex::new(Routing {
                ids,
                next: ids.start.into(),
                reuse_ids,
                pending: HashMap::new(),
                failure: None,
            }),
            budget: Arc::new(Semaphore::new(limits.buffered_bytes as usize)),
            limits,
            stopped,
        })
    }

    pub(crate) fn reserve(&self) -> ClientResult<(Arc<Lease>, mpsc::Receiver<QueuedFrame>)> {
        let mut routing = self.routing.lock().unwrap();
        if let Some(error) = routing.failure {
            return Err(ClientError::new(error));
        }
        if routing.pending.len() >= self.limits.max_in_flight {
            return Err(ClientError::new(ErrorKind::Capacity));
        }
        // With N occupied IDs, at most N+1 candidates can be needed. This also
        // avoids iterating billions of slots when the full u32 range is used.
        for _ in 0..=routing.pending.len() {
            if routing.next >= routing.ids.end_exclusive {
                return Err(ClientError::new(ErrorKind::IdRangeExhausted));
            }
            let id = routing.next as u32;
            routing.next += 1;
            if routing.reuse_ids && routing.next == routing.ids.end_exclusive {
                routing.next = routing.ids.start.into();
            }
            if routing.pending.contains_key(&id) {
                continue;
            }
            let (sender, receiver) = mpsc::channel(self.limits.queued_responses);
            let lease = Arc::new(Lease {
                id,
                admitted: AtomicBool::new(false),
                terminal: AtomicBool::new(false),
            });
            routing.pending.insert(
                id,
                Entry {
                    lease: Arc::clone(&lease),
                    sender: Some(sender),
                },
            );
            return Ok((lease, receiver));
        }
        Err(ClientError::new(ErrorKind::IdRangeExhausted))
    }

    pub(crate) fn owned(&self, id: u32) -> ClientResult<Arc<Lease>> {
        let routing = self.routing.lock().unwrap();
        if let Some(error) = routing.failure {
            return Err(ClientError::new(error));
        }
        routing
            .pending
            .get(&id)
            .filter(|entry| entry.sender.is_some())
            .map(|entry| Arc::clone(&entry.lease))
            .ok_or_else(|| ClientError::new(ErrorKind::StreamClosed))
    }

    /// Commit a packet while holding the same lock as terminal/abandon changes.
    /// No await occurs between checking ownership and crossing admission.
    pub(crate) fn admit(
        &self,
        lease: Option<&Arc<Lease>>,
        permit: mpsc::Permit<'_, WriteCommand>,
        command: WriteCommand,
    ) -> ClientResult<()> {
        let routing = self.routing.lock().unwrap();
        if let Some(error) = routing.failure {
            return Err(ClientError::new(error));
        }
        if let Some(lease) = lease {
            let owned = routing
                .pending
                .get(&lease.id)
                .is_some_and(|entry| Arc::ptr_eq(&entry.lease, lease) && entry.sender.is_some());
            if !owned {
                return Err(ClientError::new(ErrorKind::StreamClosed));
            }
            lease.admitted.store(true, Ordering::Release);
        }
        permit.send(command);
        Ok(())
    }

    pub(crate) fn abandon(&self, lease: &Arc<Lease>) {
        let mut routing = self.routing.lock().unwrap();
        let Some(entry) = routing.pending.get_mut(&lease.id) else {
            return;
        };
        if !Arc::ptr_eq(&entry.lease, lease) {
            return;
        }
        if lease.delivery() == Delivery::NotSent {
            routing.pending.remove(&lease.id);
        } else {
            // A dropped request is not a remote cancellation. Keep a tombstone
            // and count it against in-flight capacity until the peer terminates.
            entry.sender = None;
        }
    }

    pub(crate) fn close(&self, error: ErrorKind) {
        let mut routing = self.routing.lock().unwrap();
        if routing.failure.is_some() {
            return;
        }
        routing.failure = Some(error);
        routing.pending.clear();
        self.budget.close();
        self.stopped.send_replace(true);
    }

    pub(crate) fn error(&self) -> ClientError {
        ClientError::new(
            self.routing
                .lock()
                .unwrap()
                .failure
                .unwrap_or(ErrorKind::Closed),
        )
    }

    pub(crate) fn is_closed(&self) -> bool {
        *self.stopped.borrow()
    }

    pub(crate) async fn cancelled(&self) {
        let mut stopped = self.stopped.subscribe();
        let _ = stopped.wait_for(|stopped| *stopped).await;
    }

    async fn route(&self, queued: QueuedFrame) {
        let id = queued.frame.id;
        let terminal = queued.frame.flags & FLAG_TERMINAL != 0;
        let (sender, terminal_lease) = {
            let mut routing = self.routing.lock().unwrap();
            if terminal {
                match routing.pending.remove(&id) {
                    Some(entry) => (entry.sender, Some(entry.lease)),
                    None => (None, None),
                }
            } else {
                (
                    routing
                        .pending
                        .get(&id)
                        .and_then(|entry| entry.sender.clone()),
                    None,
                )
            }
        };
        if let Some(sender) = sender {
            // Bounded connection-level backpressure preserves output ordering.
            // Receiver drop wakes this send; it never stalls unrelated traffic
            // forever merely because a consumer abandoned its subscription.
            if sender.send(queued).await.is_ok()
                && let Some(lease) = terminal_lease
            {
                // Do not advertise clean completion until the terminal was
                // actually enqueued. Shutdown can interrupt backpressure.
                lease.terminal.store(true, Ordering::Release);
            }
        }
    }
}

impl Lease {
    pub(crate) fn delivery(&self) -> Delivery {
        if self.admitted.load(Ordering::Acquire) {
            Delivery::Unknown
        } else {
            Delivery::NotSent
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn reader_loop<R: AsyncRead + Unpin>(mut reader: R, state: Arc<State>) {
    let read = async {
        loop {
            let frame = read_frame(&mut reader, &state).await?;
            state.route(frame).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), ClientError>(())
    };
    tokio::select! {
        _ = state.cancelled() => {}
        result = read => if let Err(error) = result { state.close(error.kind); }
    }
}

pub(crate) async fn writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queue: mpsc::Receiver<WriteCommand>,
    state: Arc<State>,
) {
    let write = async {
        while let Some(command) = queue.recv().await {
            let result = async {
                writer.write_all(&command.packet).await?;
                writer.flush().await
            }
            .await
            .map_err(|error| ClientError::from(error).with_delivery(Delivery::Unknown));
            let failed = result.as_ref().err().copied();
            let _ = command.ack.send(result);
            if let Some(error) = failed {
                state.close(error.kind);
                return;
            }
        }
        state.close(ErrorKind::Closed);
    };
    tokio::select! {
        _ = state.cancelled() => {}
        _ = write => {}
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    state: &State,
) -> ClientResult<QueuedFrame> {
    let mut prefix = [0u8; 4];
    // Idle has no deadline. Once any byte arrives, the remaining frame has one
    // absolute deadline that trickled bytes cannot extend.
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Err(ClientError::new(ErrorKind::PeerClosed));
    }
    let deadline = state
        .limits
        .incomplete_frame_timeout
        .map(crate::options::checked_deadline)
        .transpose()?;
    let completion = async {
        reader
            .read_exact(&mut prefix[1..])
            .await
            .map_err(frame_io_error)?;
        let length = u32::from_be_bytes(prefix);
        if length < 5 || length > state.limits.max_frame_size {
            return Err(ClientError::new(ErrorKind::InvalidData));
        }
        // Validate and reserve bytes before allocating or reading the body.
        let bytes = Arc::clone(&state.budget)
            .acquire_many_owned(length + 4)
            .await
            .map_err(|_| state.error())?;
        let mut header = [0u8; 5];
        reader
            .read_exact(&mut header)
            .await
            .map_err(frame_io_error)?;
        let mut body = vec![0u8; (length - 5) as usize];
        reader.read_exact(&mut body).await.map_err(frame_io_error)?;
        let frame = RawFrame {
            id: u32::from_be_bytes(header[..4].try_into().unwrap()),
            flags: header[4],
            body,
        };
        Ok(QueuedFrame {
            frame,
            _bytes: bytes,
        })
    };
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, completion)
            .await
            .map_err(|_| ClientError::new(ErrorKind::Timeout))?,
        None => completion.await,
    }
}

fn frame_io_error(error: std::io::Error) -> ClientError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        ClientError::new(ErrorKind::TruncatedFrame)
    } else {
        error.into()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_policy_controls_whether_released_ids_can_be_reused() {
        for reuse in [false, true] {
            let state = State::new(
                IdRange {
                    start: 1,
                    end_exclusive: 2,
                },
                ClientLimits::default(),
                reuse,
            );
            let (lease, _) = state.reserve().unwrap();
            assert_eq!(lease.id, 1);
            state.abandon(&lease);
            match state.reserve() {
                Ok((next, _)) => {
                    assert!(reuse);
                    assert_eq!(next.id, 1);
                }
                Err(error) => {
                    assert!(!reuse);
                    assert_eq!(error.kind, ErrorKind::IdRangeExhausted);
                }
            }
        }
    }
}
