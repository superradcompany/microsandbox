//! Execution I/O allowances, cancellation-safe stdin writes, and output acknowledgements.

use std::sync::{Arc, Mutex};

use microsandbox_protocol::{
    exec::{ExecOutputAck, ExecStdin},
    message::MessageType,
};
use tokio::sync::{Semaphore, SemaphorePermit, mpsc, watch};

use crate::{MicrosandboxError, MicrosandboxResult, agent::AgentClient};

use super::ExecEvent;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-execution stdin capacity; caller data stays outside the SDK while waiting.
pub(crate) struct InputWindow {
    /// Remaining stdin payload allowance advertised by the guest.
    available: Semaphore,
    /// Maximum payload bytes in each stdin message.
    chunk_size: usize,
    /// Notifies writers when the guest accepts the execution.
    started: watch::Sender<bool>,
    /// Reserved and acknowledged byte offsets used to validate guest acknowledgements.
    offsets: Mutex<Offsets>,
    /// Wakes writers if the execution ends before it starts.
    closed: watch::Sender<bool>,
}

/// Stdin capacity held until queue admission commits it or cancellation returns it.
pub(super) struct InputReservation<'a> {
    /// Execution allowance that owns this reservation.
    window: &'a InputWindow,
    /// Capacity returned on cancellation unless committed to the transport queue.
    permit: Option<SemaphorePermit<'a>>,
    /// Payload bytes to roll back from the reserved offset if cancelled.
    bytes: u32,
}

#[derive(Default)]
struct Offsets {
    /// Cumulative bytes reserved for sending, including reservations not yet committed.
    sent: u64,
    /// Cumulative bytes acknowledged as delivered into the child stdin.
    consumed: u64,
}

/// Acknowledges output when consumed or discarded, rather than when received.
pub(crate) struct EventReceiver {
    /// Unread events retained for this execution.
    events: mpsc::UnboundedReceiver<ExecEvent>,
    /// Consumption notifications; absent when the guest uses legacy buffering.
    consumed: Option<watch::Sender<ExecOutputAck>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InputWindow {
    pub(crate) fn new(bytes: u32, chunk_size: usize) -> Arc<Self> {
        Arc::new(Self {
            available: Semaphore::new(bytes as usize),
            chunk_size,
            started: watch::channel(false).0,
            offsets: Mutex::new(Offsets::default()),
            closed: watch::channel(false).0,
        })
    }

    /// Send caller data in chunks, reserving capacity until each frame is committed.
    pub(crate) async fn send(
        &self,
        client: &AgentClient,
        id: u32,
        data: impl AsRef<[u8]>,
    ) -> MicrosandboxResult<()> {
        let data = data.as_ref();
        for chunk in data.chunks(self.chunk_size) {
            let reservation = self.reserve(chunk.len() as u32).await?;
            client
                .send_and_commit(
                    id,
                    MessageType::ExecStdin,
                    &ExecStdin {
                        data: chunk.to_vec(),
                    },
                    || reservation.commit(),
                )
                .await?;
        }
        Ok(())
    }

    pub(super) async fn reserve(&self, bytes: u32) -> MicrosandboxResult<InputReservation<'_>> {
        let permit = self
            .available
            .acquire_many(bytes)
            .await
            .map_err(|_| MicrosandboxError::Runtime("execution stdin closed".into()))?;
        let mut offsets = self.offsets.lock().unwrap();
        offsets.sent = offsets
            .sent
            .checked_add(u64::from(bytes))
            .ok_or_else(|| MicrosandboxError::Runtime("execution stdin offset overflow".into()))?;
        Ok(InputReservation {
            window: self,
            permit: Some(permit),
            bytes,
        })
    }

    pub(crate) fn acknowledge(&self, consumed: u64) -> bool {
        let mut offsets = self.offsets.lock().unwrap();
        if consumed < offsets.consumed || consumed > offsets.sent {
            return false;
        }
        self.available
            .add_permits((consumed - offsets.consumed) as usize);
        offsets.consumed = consumed;
        true
    }

    pub(crate) fn mark_started(&self) {
        self.started.send_replace(true);
    }

    pub(crate) async fn wait_started(&self) -> MicrosandboxResult<()> {
        let mut started = self.started.subscribe();
        let mut closed = self.closed.subscribe();
        tokio::select! {
            result = started.wait_for(|started| *started) => result.map(|_| ()).map_err(|_| stdin_closed()),
            _ = closed.wait_for(|closed| *closed) => Err(stdin_closed()),
        }
    }

    pub(crate) fn close(&self) {
        self.available.close();
        self.closed.send_replace(true);
    }
}

impl InputReservation<'_> {
    pub(super) fn commit(mut self) {
        self.permit.take().unwrap().forget();
    }
}

impl EventReceiver {
    pub(super) fn new(
        events: mpsc::UnboundedReceiver<ExecEvent>,
        controlled: bool,
    ) -> (EventReceiver, Option<OutputAcknowledgements>) {
        let (consumed, acknowledgements) = if controlled {
            let acknowledgements = OutputAcknowledgements::default();
            (
                Some(acknowledgements.consumed.clone()),
                Some(acknowledgements),
            )
        } else {
            (None, None)
        };
        (EventReceiver { events, consumed }, acknowledgements)
    }

    pub(crate) async fn recv(&mut self) -> Option<ExecEvent> {
        let event = self.events.recv().await?;
        if let Some(consumed) = &self.consumed {
            consume(consumed, &event);
        }
        Some(event)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for InputReservation<'_> {
    fn drop(&mut self) {
        if self.permit.is_some() {
            let mut offsets = self.window.offsets.lock().unwrap();
            offsets.sent -= u64::from(self.bytes);
        }
    }
}

impl Drop for EventReceiver {
    fn drop(&mut self) {
        // Stop new deliveries before returning capacity for every queued event.
        self.events.close();
        if let Some(consumed) = &self.consumed {
            while let Ok(event) = self.events.try_recv() {
                consume(consumed, &event);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn stdin_closed() -> MicrosandboxError {
    MicrosandboxError::Runtime("execution stdin closed".into())
}

/// Return capacity for output read by the caller or discarded after its reader is dropped.
pub(super) fn consume(consumed: &watch::Sender<ExecOutputAck>, event: &ExecEvent) {
    if let ExecEvent::Stdout(data) | ExecEvent::Stderr(data) = event {
        consumed.send_modify(|acknowledgement| {
            acknowledgement
                .consume(data.len())
                .expect("execution output counter overflow");
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use microsandbox_protocol::exec::EXEC_OUTPUT_EVENT_OVERHEAD;

    use super::*;

    #[tokio::test]
    async fn unread_output_sends_no_acknowledgement_and_reads_coalesce() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (mut events, acknowledgements) = EventReceiver::new(rx, true);
        let mut acknowledgements = acknowledgements.unwrap().consumed.subscribe();
        tx.send(ExecEvent::Started { pid: 1 }).unwrap();
        tx.send(ExecEvent::Stdout(Bytes::from_static(b"abc")))
            .unwrap();
        tx.send(ExecEvent::Stderr(Bytes::from_static(b"defg")))
            .unwrap();
        assert!(!acknowledgements.has_changed().unwrap());
        events.recv().await.unwrap();
        assert!(!acknowledgements.has_changed().unwrap());
        events.recv().await.unwrap();
        events.recv().await.unwrap();
        assert_eq!(
            acknowledgements.borrow_and_update().consumed,
            7 + 2 * u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        );
        tx.send(ExecEvent::Stdout(Bytes::from_static(b"unread")))
            .unwrap();
        drop(events);
        assert!(tx.is_closed());
        assert_eq!(
            acknowledgements.borrow().consumed,
            13 + 3 * u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(super) use microsandbox_agent_client::OutputAcknowledgements;
